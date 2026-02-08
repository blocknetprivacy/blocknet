package main

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Explorer serves the block explorer web interface
type Explorer struct {
	daemon *Daemon
	mux    *http.ServeMux
}

// NewExplorer creates a new explorer server
func NewExplorer(daemon *Daemon) *Explorer {
	e := &Explorer{daemon: daemon, mux: http.NewServeMux()}
	e.mux.HandleFunc("/", e.handleIndex)
	e.mux.HandleFunc("/block/", e.handleBlock)
	e.mux.HandleFunc("/tx/", e.handleTx)
	e.mux.HandleFunc("/search", e.handleSearch)
	return e
}

// ServeHTTP implements http.Handler
func (e *Explorer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mux.ServeHTTP(w, r)
}

// Start starts the explorer HTTP server
func (e *Explorer) Start(addr string) error {
	return http.ListenAndServe(addr, e)
}

// Supply info
func (e *Explorer) getSupplyInfo() (emitted, remaining uint64, pctEmitted float64) {
	height := e.daemon.chain.Height()

	// Calculate emitted supply
	for h := uint64(1); h <= height; h++ {
		emitted += GetBlockReward(h)
	}

	// Target supply is ~10M coins (before tail emission)
	targetSupply := uint64(10_000_000 * 100_000_000) // in smallest units
	if emitted >= targetSupply {
		remaining = 0
		pctEmitted = 100.0
	} else {
		remaining = targetSupply - emitted
		pctEmitted = float64(emitted) / float64(targetSupply) * 100
	}
	return
}

func (e *Explorer) handleIndex(w http.ResponseWriter, r *http.Request) {
	chain := e.daemon.chain
	height := chain.Height()

	// Get recent blocks
	type blockSummary struct {
		Height     uint64
		Hash       string
		Time       string
		Ago        string
		TxCount    int
		Difficulty uint64
	}

	var blocks []blockSummary

	for h := height; h > 0 && len(blocks) < 20; h-- {
		block := chain.GetBlockByHeight(h)
		if block == nil {
			continue
		}
		hash := block.Hash()
		blocks = append(blocks, blockSummary{
			Height:     h,
			Hash:       fmt.Sprintf("%x", hash[:]),
			Time:       time.Unix(block.Header.Timestamp, 0).UTC().Format("2006-01-02 15:04:05"),
			Ago:        timeAgo(block.Header.Timestamp),
			TxCount:    len(block.Transactions),
			Difficulty: block.Header.Difficulty,
		})
	}

	emitted, remaining, pctEmitted := e.getSupplyInfo()

	// Get miner stats
	// Estimate network hashrate from recent block times and difficulty
	// hashrate ≈ difficulty / average_block_time
	var hashrate float64
	if height >= 2 {
		// Get last few blocks to estimate average block time
		var totalTime int64
		var count int
		for h := height; h > 0 && count < 10; h-- {
			block := chain.GetBlockByHeight(h)
			prevBlock := chain.GetBlockByHeight(h - 1)
			if block != nil && prevBlock != nil {
				blockTime := block.Header.Timestamp - prevBlock.Header.Timestamp
				if blockTime > 0 {
					totalTime += blockTime
					count++
				}
			}
		}
		if count > 0 && totalTime > 0 {
			avgBlockTime := float64(totalTime) / float64(count)
			// Each hash at current difficulty takes avgBlockTime seconds on average
			// So hashrate = difficulty / avgBlockTime
			hashrate = float64(chain.NextDifficulty()) / avgBlockTime
		}
	}

	data := map[string]interface{}{
		"Height":      height,
		"Difficulty":  chain.NextDifficulty(),
		"Peers":       len(e.daemon.node.Peers()),
		"Hashrate":    fmt.Sprintf("%.2f", hashrate),
		"Emitted":     float64(emitted) / 100_000_000,
		"Remaining":   float64(remaining) / 100_000_000,
		"PctEmitted":  fmt.Sprintf("%.4f", pctEmitted),
		"TailStarted": pctEmitted >= 100,
		"Blocks":      blocks,
	}

	renderTemplate(w, explorerIndexTmpl, data)
}

func (e *Explorer) handleBlock(w http.ResponseWriter, r *http.Request) {
	// Extract block ID from path: /block/{id}
	path := strings.TrimPrefix(r.URL.Path, "/block/")
	if path == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	chain := e.daemon.chain
	var block *Block

	// Try as height first
	if height, parseErr := strconv.ParseUint(path, 10, 64); parseErr == nil {
		block = chain.GetBlockByHeight(height)
	} else {
		// Try as hash
		if len(path) >= 64 {
			hashBytes, err := hex.DecodeString(path[:64])
			if err == nil && len(hashBytes) == 32 {
				var hash [32]byte
				copy(hash[:], hashBytes)
				block = chain.GetBlock(hash)
			}
		}
	}

	if block == nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	hash := block.Hash()

	type txSummary struct {
		Hash       string
		IsCoinbase bool
		Inputs     int
		Outputs    int
	}

	var txs []txSummary
	for i, tx := range block.Transactions {
		txHash, _ := tx.TxID()
		txs = append(txs, txSummary{
			Hash:       fmt.Sprintf("%x", txHash[:]),
			IsCoinbase: i == 0 && block.Header.Height > 0,
			Inputs:     len(tx.Inputs),
			Outputs:    len(tx.Outputs),
		})
	}

	// Genesis block has a special message in the hash preimage
	genesisMsg := ""
	if block.Header.Height == 0 {
		genesisMsg = `sha3.256("CNBC 02/Feb/2026 Bitcoin is coming off a brutal week")`
	}

	data := map[string]interface{}{
		"Height":     block.Header.Height,
		"Hash":       fmt.Sprintf("%x", hash[:]),
		"PrevHash":   fmt.Sprintf("%x", block.Header.PrevHash[:]),
		"MerkleRoot": fmt.Sprintf("%x", block.Header.MerkleRoot[:]),
		"Time":       time.Unix(block.Header.Timestamp, 0).UTC().Format("2006-01-02 15:04:05 UTC"),
		"Difficulty": block.Header.Difficulty,
		"Nonce":      block.Header.Nonce,
		"TxCount":    len(block.Transactions),
		"Txs":        txs,
		"HasPrev":    block.Header.Height > 0,
		"PrevHeight": block.Header.Height - 1,
		"NextHeight": block.Header.Height + 1,
		"HasNext":    block.Header.Height < chain.Height(),
		"Reward":     float64(GetBlockReward(block.Header.Height)) / 100_000_000,
		"IsGenesis":  block.Header.Height == 0,
		"GenesisMsg": genesisMsg,
	}

	renderTemplate(w, explorerBlockTmpl, data)
}

func (e *Explorer) handleTx(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/tx/")
	if path == "" || len(path) < 64 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Search for tx in blocks
	tx, blockHeight, found := e.findTx(path)
	if !found {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}

	txID, _ := tx.TxID()
	isCoinbase := len(tx.Inputs) == 0

	// Build inputs data
	var inputs []map[string]interface{}
	for i, inp := range tx.Inputs {
		inputs = append(inputs, map[string]interface{}{
			"Index":        i,
			"KeyImage":     fmt.Sprintf("%x", inp.KeyImage),
			"RingSize":     len(inp.RingMembers),
			"PseudoOutput": fmt.Sprintf("%x", inp.PseudoOutput),
		})
	}

	// Build outputs data
	var outputs []map[string]interface{}
	for i, out := range tx.Outputs {
		outputs = append(outputs, map[string]interface{}{
			"Index":      i,
			"Commitment": fmt.Sprintf("%x", out.Commitment),
			"PublicKey":  fmt.Sprintf("%x", out.PublicKey),
			"RangeProof": len(out.RangeProof),
		})
	}

	confirmations := e.daemon.chain.Height() - blockHeight + 1

	data := map[string]interface{}{
		"Hash":          fmt.Sprintf("%x", txID),
		"BlockHeight":   blockHeight,
		"Confirmations": confirmations,
		"IsCoinbase":    isCoinbase,
		"Fee":           float64(tx.Fee) / 1e9,
		"TxPubKey":      fmt.Sprintf("%x", tx.TxPublicKey),
		"InputCount":    len(tx.Inputs),
		"OutputCount":   len(tx.Outputs),
		"Inputs":        inputs,
		"Outputs":       outputs,
	}

	renderTemplate(w, explorerTxTmpl, data)
}

// findTx searches for a transaction by hash in the blockchain.
func (e *Explorer) findTx(hashStr string) (*Transaction, uint64, bool) {
	return e.daemon.chain.FindTxByHashStr(hashStr)
}

func (e *Explorer) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Try as block height
	if height, err := strconv.ParseUint(q, 10, 64); err == nil {
		if height <= e.daemon.chain.Height() {
			http.Redirect(w, r, "/block/"+q, http.StatusFound)
			return
		}
	}

	// Try as block or tx hash (64 hex chars)
	if len(q) == 64 {
		// First check if it's a block hash
		var hash [32]byte
		if decoded, err := hex.DecodeString(q); err == nil && len(decoded) == 32 {
			copy(hash[:], decoded)
			if e.daemon.chain.GetBlock(hash) != nil {
				http.Redirect(w, r, "/block/"+q, http.StatusFound)
				return
			}
		}

		// Then check if it's a tx hash
		if _, _, found := e.findTx(q); found {
			http.Redirect(w, r, "/tx/"+q, http.StatusFound)
			return
		}

		// Default to block (will show not found if invalid)
		http.Redirect(w, r, "/block/"+q, http.StatusFound)
		return
	}

	http.Error(w, "Not found: "+q, http.StatusNotFound)
}

func timeAgo(timestamp int64) string {
	diff := time.Now().Unix() - timestamp
	if diff < 60 {
		return fmt.Sprintf("%ds ago", diff)
	} else if diff < 3600 {
		return fmt.Sprintf("%dm ago", diff/60)
	} else if diff < 86400 {
		return fmt.Sprintf("%dh ago", diff/3600)
	}
	return fmt.Sprintf("%dd ago", diff/86400)
}

func renderTemplate(w http.ResponseWriter, tmplStr string, data interface{}) {
	tmpl, err := template.New("page").Parse(tmplStr)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// Base CSS matches website exactly, with explorer-specific additions
const explorerCSS = `*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#b0b0b0;font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;padding:32px;max-width:800px;margin:0 auto}
a{color:#af0}
a:hover{color:#cf3}
h1,h2{color:#eee;font-weight:normal;margin:48px 0 16px}
h1{font-size:24px;margin-top:0}
h2{font-size:18px;border-bottom:1px dashed #333;padding-bottom:8px}
p{margin:16px 0}
.g{color:#af0}
.d{color:#555}
.box{border:1px solid #333;padding:20px;margin:24px 0;background:#0d0d0d}
.stats{display:flex;justify-content:space-between}
.spec{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #1a1a1a}
.spec:last-child{border:0}
.spec-k{color:#666}
footer{margin-top:64px;padding-top:24px;border-top:1px dashed #333;color:#444;font-size:13px}
@media(max-width:600px){body{padding:16px}h1{font-size:20px}}
.stat{text-align:center}
.stat-v{font-size:24px;color:#eee}
.stat-k{font-size:12px;color:#666;text-transform:uppercase}
table{width:100%;border-collapse:collapse;margin:16px 0}
th,td{text-align:left;padding:12px;border-bottom:1px solid #222}
th{color:#666;font-weight:normal;font-size:13px;text-transform:uppercase}
tr:hover{background:#111}
.hash{color:#666;font-size:13px}
.search{display:flex;gap:8px;margin:24px 0}
.search input{flex:1;background:#111;border:1px solid #333;color:#eee;padding:12px;font:inherit}
.search input:focus{outline:none;border-color:#af0}
.search button{background:#af0;border:0;color:#000;padding:12px 24px;cursor:pointer;font:inherit}
.search button:hover{background:#cf3}
.nav{margin:24px 0}
.nav a{margin-right:16px}
.prop{display:flex;padding:8px 0;border-bottom:1px solid #1a1a1a}
.prop:last-child{border:0}
.prop-k{width:140px;color:#666}
.prop-v{flex:1;word-break:break-all}
.prop-v.mono{font-size:12px;color:#888}`

const explorerIndexTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>blocknet explorer</title>
<meta name="description" content="Zero-knowledge money">
<meta property="og:title" content="blocknet explorer">
<meta property="og:description" content="Zero-knowledge money">
<meta property="og:image" content="https://blocknetcrypto.com/blocknet.png">
<meta property="og:image:width" content="1024">
<meta property="og:image:height" content="1024">
<meta property="og:url" content="https://explorer.blocknetcrypto.com">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0a0a0a">
<link rel="icon" type="image/x-icon" href="https://blocknetcrypto.com/favicon.ico">
<style>` + explorerCSS + `</style>
</head>
<body>
<h1><span class="g">$</span> blocknet <span class="d">explorer</span></h1>

<form class="search" action="/search" method="get">
<input type="text" name="q" placeholder="Search by block height or hash...">
<button type="submit">Search</button>
</form>

<div class="box stats">
<div class="stat"><div class="stat-v">{{.Height}}</div><div class="stat-k">Block Height</div></div>
<div class="stat"><div class="stat-v">{{.Peers}}</div><div class="stat-k">Peers</div></div>
<div class="stat"><div class="stat-v">{{.Difficulty}}</div><div class="stat-k">Difficulty</div></div>
<div class="stat"><div class="stat-v">{{.Hashrate}} H/s</div><div class="stat-k">Network Hashrate</div></div>
</div>

<h2><span class="g">#</span> supply</h2>
<div class="box stats">
<div class="stat"><div class="stat-v">{{printf "%.2f" .Emitted}}</div><div class="stat-k">Coins Emitted</div></div>
<div class="stat"><div class="stat-v">{{printf "%.2f" .Remaining}}</div><div class="stat-k">Remaining (pre-tail)</div></div>
<div class="stat"><div class="stat-v">{{.PctEmitted}}%</div><div class="stat-k">Emission Progress</div></div>
{{if .TailStarted}}<div class="stat"><div class="stat-v" style="color:#af0">Active</div><div class="stat-k">Tail Emission</div></div>{{end}}
</div>

<h2><span class="g">#</span> recent blocks</h2>
<table>
<tr><th>Height</th><th>Hash</th><th>Age</th><th>Txs</th></tr>
{{range .Blocks}}
<tr>
<td><a href="/block/{{.Height}}">{{.Height}}</a></td>
<td class="hash"><a href="/block/{{.Hash}}">{{slice .Hash 0 16}}...</a></td>
<td>{{.Ago}}</td>
<td>{{.TxCount}}</td>
</tr>
{{end}}
</table>

<footer><a href="https://blocknetcrypto.com">← blocknetcrypto.com</a></footer>
</body>
</html>`

const explorerBlockTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Block {{.Height}} - blocknet explorer</title>
<meta name="description" content="Zero-knowledge money">
<meta property="og:title" content="Block {{.Height}} - blocknet">
<meta property="og:description" content="Zero-knowledge money">
<meta property="og:image" content="https://blocknetcrypto.com/blocknet.png">
<meta property="og:image:width" content="1024">
<meta property="og:image:height" content="1024">
<meta property="og:url" content="https://explorer.blocknetcrypto.com/block/{{.Height}}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0a0a0a">
<link rel="icon" type="image/x-icon" href="https://blocknetcrypto.com/favicon.ico">
<style>` + explorerCSS + `</style>
</head>
<body>
<h1><a href="/" style="text-decoration:none;color:#eee"><span class="g">$</span> blocknet <span class="d">explorer</span></a></h1>

<div class="nav">
{{if .HasPrev}}<a href="/block/{{.PrevHeight}}">← Block {{.PrevHeight}}</a>{{end}}
{{if .HasNext}}<a href="/block/{{.NextHeight}}">Block {{.NextHeight}} →</a>{{end}}
</div>

<h2><span class="g">#</span> block {{.Height}}</h2>
<div class="box">
<div class="prop"><div class="prop-k">Hash</div><div class="prop-v mono">{{if .IsGenesis}}<span title="{{.GenesisMsg}}" style="cursor:help;border-bottom:1px dashed #af0">{{.Hash}}</span>{{else}}{{.Hash}}{{end}}</div></div>
<div class="prop"><div class="prop-k">Previous</div><div class="prop-v mono"><a href="/block/{{.PrevHash}}">{{.PrevHash}}</a></div></div>
<div class="prop"><div class="prop-k">Merkle Root</div><div class="prop-v mono">{{.MerkleRoot}}</div></div>
<div class="prop"><div class="prop-k">Time</div><div class="prop-v">{{.Time}}</div></div>
<div class="prop"><div class="prop-k">Difficulty</div><div class="prop-v">{{.Difficulty}}</div></div>
<div class="prop"><div class="prop-k">Nonce</div><div class="prop-v">{{.Nonce}}</div></div>
<div class="prop"><div class="prop-k">Block Reward</div><div class="prop-v">{{printf "%.8f" .Reward}} BNT</div></div>
<div class="prop"><div class="prop-k">Transactions</div><div class="prop-v">{{.TxCount}}</div></div>
</div>

<h2><span class="g">#</span> transactions</h2>
<table>
<tr><th>Hash</th><th>Type</th><th>Inputs</th><th>Outputs</th></tr>
{{range .Txs}}
<tr>
<td class="hash"><a href="/tx/{{.Hash}}">{{slice .Hash 0 24}}...</a></td>
<td>{{if .IsCoinbase}}<span class="g">coinbase</span>{{else}}transfer{{end}}</td>
<td>{{.Inputs}}</td>
<td>{{.Outputs}}</td>
</tr>
{{end}}
</table>

<footer><a href="/">← explorer</a> · <a href="https://blocknetcrypto.com">blocknetcrypto.com</a></footer>
</body>
</html>`

const explorerTxTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Transaction - blocknet explorer</title>
<meta name="description" content="Zero-knowledge money">
<meta property="og:title" content="Transaction - blocknet">
<meta property="og:description" content="Zero-knowledge money">
<meta property="og:image" content="https://blocknetcrypto.com/blocknet.png">
<meta property="og:image:width" content="1024">
<meta property="og:image:height" content="1024">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0a0a0a">
<link rel="icon" type="image/x-icon" href="https://blocknetcrypto.com/favicon.ico">
<style>` + explorerCSS + `</style>
</head>
<body>
<h1><a href="/" style="text-decoration:none;color:#eee"><span class="g">$</span> blocknet <span class="d">explorer</span></a></h1>

<h2><span class="g">#</span> transaction</h2>
<div class="box">
<div class="prop"><div class="prop-k">Hash</div><div class="prop-v mono">{{.Hash}}</div></div>
<div class="prop"><div class="prop-k">Block</div><div class="prop-v"><a href="/block/{{.BlockHeight}}">{{.BlockHeight}}</a> ({{.Confirmations}} confirmations)</div></div>
<div class="prop"><div class="prop-k">Type</div><div class="prop-v">{{if .IsCoinbase}}<span class="g">coinbase</span>{{else}}transfer{{end}}</div></div>
{{if not .IsCoinbase}}<div class="prop"><div class="prop-k">Fee</div><div class="prop-v">{{printf "%.9f" .Fee}} BNT</div></div>{{end}}
<div class="prop"><div class="prop-k">Inputs</div><div class="prop-v">{{.InputCount}}</div></div>
<div class="prop"><div class="prop-k">Outputs</div><div class="prop-v">{{.OutputCount}}</div></div>
<div class="prop"><div class="prop-k">Tx Public Key</div><div class="prop-v mono">{{.TxPubKey}}</div></div>
</div>

{{if .Inputs}}
<h2><span class="g">#</span> inputs (ring signatures)</h2>
<p class="d" style="font-size:13px;margin-bottom:16px">Each input uses a ring of {{(index .Inputs 0).RingSize}} public keys. The real spender is hidden among decoys.</p>
{{range .Inputs}}
<div class="box">
<div class="prop"><div class="prop-k">Input #{{.Index}}</div><div class="prop-v"></div></div>
<div class="prop"><div class="prop-k">Key Image</div><div class="prop-v mono">{{.KeyImage}}</div></div>
<div class="prop"><div class="prop-k">Ring Size</div><div class="prop-v">{{.RingSize}}</div></div>
<div class="prop"><div class="prop-k">Pseudo Output</div><div class="prop-v mono">{{.PseudoOutput}}</div></div>
</div>
{{end}}
{{end}}

<h2><span class="g">#</span> outputs (stealth addresses)</h2>
<p class="d" style="font-size:13px;margin-bottom:16px">Amounts are hidden by Pedersen commitments. Range proofs ensure validity without revealing values.</p>
{{range .Outputs}}
<div class="box">
<div class="prop"><div class="prop-k">Output #{{.Index}}</div><div class="prop-v"></div></div>
<div class="prop"><div class="prop-k">Stealth Address</div><div class="prop-v mono">{{.PublicKey}}</div></div>
<div class="prop"><div class="prop-k">Commitment</div><div class="prop-v mono">{{.Commitment}}</div></div>
<div class="prop"><div class="prop-k">Range Proof</div><div class="prop-v">{{.RangeProof}} bytes (Bulletproof)</div></div>
</div>
{{end}}

<footer><a href="/">← explorer</a> · <a href="https://blocknetcrypto.com">blocknetcrypto.com</a></footer>
</body>
</html>`
