package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Node represents a blockchain node
type Node struct {
	ID         string                 `json:"id"`
	Address    string                 `json:"address"`
	Port       int                    `json:"port"`
	Peers      map[string]*Peer       `json:"peers"`
	Blockchain *Blockchain           `json:"blockchain"`
	Mempool    []*Transaction         `json:"mempool"`
	mutex      sync.RWMutex
	listener   net.Listener
}

// Peer represents a connected peer
type Peer struct {
	ID      string    `json:"id"`
	Address string    `json:"address"`
	Conn    net.Conn  `json:"-"` // 직렬화에서 제외
	LastSeen time.Time `json:"lastSeen"`
}

// Message represents network message
type Message struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	Data    interface{} `json:"data"`
	Timestamp uint64    `json:"timestamp"`
}

// Blockchain represents the chain of blocks
type Blockchain struct {
	Blocks []*Block `json:"blocks"`
	mutex  sync.RWMutex
}

// NewNode creates a new blockchain node
func NewNode(id, address string, port int) *Node {
	return &Node{
		ID:         id,
		Address:    address,
		Port:       port,
		Peers:      make(map[string]*Peer),
		Blockchain: &Blockchain{Blocks: []*Block{}},
		Mempool:    []*Transaction{},
	}
}

// Start starts the node server
func (n *Node) Start() error {
	addr := fmt.Sprintf("%s:%d", n.Address, n.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}
	
	n.listener = listener
	fmt.Printf("Node %s started on %s\n", n.ID, addr)
	
	// Accept incoming connections
	go n.acceptConnections()
	
	return nil
}

// acceptConnections handles incoming peer connections
func (n *Node) acceptConnections() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		
		go n.handlePeerConnection(conn)
	}
}

// handlePeerConnection handles communication with a peer
func (n *Node) handlePeerConnection(conn net.Conn) {
	defer conn.Close()
	
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var msg Message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			log.Printf("Error decoding message: %v", err)
			continue
		}
		
		n.handleMessage(&msg, conn)
	}
}

// handleMessage processes received messages
func (n *Node) handleMessage(msg *Message, conn net.Conn) {
	switch msg.Type {
	case "ping":
		n.handlePing(msg, conn)
	case "new_block":
		n.handleNewBlock(msg)
	case "new_transaction":
		n.handleNewTransaction(msg)
	case "get_blockchain":
		n.handleGetBlockchain(conn)
	case "blockchain_response":
		n.handleBlockchainResponse(msg)
	case "peer_discovery":
		n.handlePeerDiscovery(msg, conn)
	case "tendermint_proposal":
		n.handleTendermintProposal(msg)
	case "tendermint_vote":
		n.handleTendermintVote(msg)
	case "validator_info":
		n.handleValidatorInfo(msg)
	case "staking_event":
		n.handleStakingEvent(msg)
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

// handlePing responds to ping messages
func (n *Node) handlePing(msg *Message, conn net.Conn) {
	response := Message{
		Type:      "pong",
		From:      n.ID,
		Data:      "pong",
		Timestamp: uint64(time.Now().Unix()),
	}
	n.sendMessage(conn, &response)
}

// handleNewBlock processes new block announcements
func (n *Node) handleNewBlock(msg *Message) {
	blockData, ok := msg.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid block data")
		return
	}
	
	// Convert map to Block struct (simplified)
	blockJSON, _ := json.Marshal(blockData)
	var block Block
	if err := json.Unmarshal(blockJSON, &block); err != nil {
		log.Printf("Error unmarshaling block: %v", err)
		return
	}
	
	if n.validateAndAddBlock(&block) {
		fmt.Printf("Node %s: Added new block #%d\n", n.ID, block.Number)
		// 다른 피어들에게 전파 (자신에게 보낸 피어 제외)
		n.broadcastToOthers(&Message{
			Type:      "new_block",
			From:      n.ID,
			Data:      &block,
			Timestamp: uint64(time.Now().Unix()),
		}, msg.From)
	}
}

// handleNewTransaction processes new transaction announcements
func (n *Node) handleNewTransaction(msg *Message) {
	txData, ok := msg.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid transaction data")
		return
	}
	
	// Convert to Transaction struct (simplified)
	txJSON, _ := json.Marshal(txData)
	var tx Transaction
	if err := json.Unmarshal(txJSON, &tx); err != nil {
		log.Printf("Error unmarshaling transaction: %v", err)
		return
	}
	
	n.addToMempool(&tx)
	fmt.Printf("Node %s: Added transaction to mempool\n", n.ID)
}

// ConnectToPeer connects to another node
func (n *Node) ConnectToPeer(peerAddress string) error {
	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		return fmt.Errorf("failed to connect to peer %s: %v", peerAddress, err)
	}
	
	peer := &Peer{
		ID:      fmt.Sprintf("peer_%s", peerAddress),
		Address: peerAddress,
		Conn:    conn,
		LastSeen: time.Now(),
	}
	
	n.mutex.Lock()
	n.Peers[peer.ID] = peer
	n.mutex.Unlock()
	
	fmt.Printf("Node %s connected to peer %s\n", n.ID, peerAddress)
	
	// Send peer discovery message
	discoveryMsg := Message{
		Type:      "peer_discovery",
		From:      n.ID,
		Data:      fmt.Sprintf("%s:%d", n.Address, n.Port),
		Timestamp: uint64(time.Now().Unix()),
	}
	n.sendMessage(conn, &discoveryMsg)
	
	// Start listening to this peer
	go n.handlePeerConnection(conn)
	
	return nil
}

// BroadcastBlock broadcasts a new block to all peers
func (n *Node) BroadcastBlock(block *Block) {
	msg := Message{
		Type:      "new_block",
		From:      n.ID,
		Data:      block,
		Timestamp: uint64(time.Now().Unix()),
	}
	
	n.broadcastToAll(&msg)
	fmt.Printf("Node %s: Broadcasted block #%d to %d peers\n", 
		n.ID, block.Number, len(n.Peers))
}

// BroadcastTransaction broadcasts a new transaction to all peers
func (n *Node) BroadcastTransaction(tx *Transaction) {
	msg := Message{
		Type:      "new_transaction",
		From:      n.ID,
		Data:      tx,
		Timestamp: uint64(time.Now().Unix()),
	}
	
	n.broadcastToAll(&msg)
	fmt.Printf("Node %s: Broadcasted transaction to %d peers\n", 
		n.ID, len(n.Peers))
}

// broadcastToAll sends message to all connected peers
func (n *Node) broadcastToAll(msg *Message) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	
	for _, peer := range n.Peers {
		go n.sendMessage(peer.Conn, msg)
	}
}

// broadcastToOthers sends message to all peers except specified one
func (n *Node) broadcastToOthers(msg *Message, except string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	
	for peerID, peer := range n.Peers {
		if peerID != except {
			go n.sendMessage(peer.Conn, msg)
		}
	}
}

// sendMessage sends a message to a connection
func (n *Node) sendMessage(conn net.Conn, msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling message: %v", err)
		return
	}
	
	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		log.Printf("Error sending message: %v", err)
	}
}

// validateAndAddBlock validates and adds a block to the blockchain
func (n *Node) validateAndAddBlock(block *Block) bool {
	n.Blockchain.mutex.Lock()
	defer n.Blockchain.mutex.Unlock()
	
	// 간단한 검증: 블록 번호가 연속적인지 확인
	if len(n.Blockchain.Blocks) > 0 {
		lastBlock := n.Blockchain.Blocks[len(n.Blockchain.Blocks)-1]
		if block.Number != lastBlock.Number+1 {
			log.Printf("Invalid block number: expected %d, got %d", 
				lastBlock.Number+1, block.Number)
			return false
		}
	}
	
	n.Blockchain.Blocks = append(n.Blockchain.Blocks, block)
	return true
}

// addToMempool adds transaction to mempool
func (n *Node) addToMempool(tx *Transaction) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	
	// 중복 체크 (간단한 방식)
	for _, existing := range n.Mempool {
		if existing.Hash() == tx.Hash() {
			return // 이미 있음
		}
	}
	
	n.Mempool = append(n.Mempool, tx)
}

// GetBlockchainLength returns the length of blockchain
func (n *Node) GetBlockchainLength() int {
	n.Blockchain.mutex.RLock()
	defer n.Blockchain.mutex.RUnlock()
	return len(n.Blockchain.Blocks)
}

// GetMempoolSize returns the size of mempool
func (n *Node) GetMempoolSize() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return len(n.Mempool)
}

// handlePeerDiscovery handles peer discovery messages
func (n *Node) handlePeerDiscovery(msg *Message, conn net.Conn) {
	peerAddr, ok := msg.Data.(string)
	if !ok {
		return
	}
	
	fmt.Printf("Node %s: Discovered peer %s\n", n.ID, peerAddr)
	// 필요시 새로운 피어에 연결하는 로직 추가 가능
}

// handleGetBlockchain handles blockchain request
func (n *Node) handleGetBlockchain(conn net.Conn) {
	n.Blockchain.mutex.RLock()
	blockchain := n.Blockchain.Blocks
	n.Blockchain.mutex.RUnlock()
	
	response := Message{
		Type:      "blockchain_response",
		From:      n.ID,
		Data:      blockchain,
		Timestamp: uint64(time.Now().Unix()),
	}
	n.sendMessage(conn, &response)
}

// handleBlockchainResponse handles blockchain response
func (n *Node) handleBlockchainResponse(msg *Message) {
	// 블록체인 동기화 로직 (간단한 버전)
	blocksData, ok := msg.Data.([]interface{})
	if !ok {
		return
	}
	
	if len(blocksData) > n.GetBlockchainLength() {
		fmt.Printf("Node %s: Received longer blockchain, updating...\n", n.ID)
		// 실제로는 더 복잡한 검증이 필요
	}
}

// Stop stops the node
func (n *Node) Stop() {
	if n.listener != nil {
		n.listener.Close()
	}
	
	n.mutex.Lock()
	for _, peer := range n.Peers {
		peer.Conn.Close()
	}
	n.mutex.Unlock()
	
	fmt.Printf("Node %s stopped\n", n.ID)
}

// MineBlock mines a new block from mempool transactions
func (n *Node) MineBlock() *Block {
	n.mutex.Lock()
	transactions := make([]*Transaction, len(n.Mempool))
	copy(transactions, n.Mempool)
	n.Mempool = []*Transaction{} // 멤풀 비우기
	n.mutex.Unlock()
	
	if len(transactions) == 0 {
		return nil
	}
	
	// 새 블록 생성
	blockNumber := uint64(n.GetBlockchainLength())
	var parentHash Hash
	if blockNumber > 0 {
		n.Blockchain.mutex.RLock()
		parentHash = n.Blockchain.Blocks[blockNumber-1].TxRoot
		n.Blockchain.mutex.RUnlock()
	}
	
	builder := NewBlockBuilder(blockNumber, parentHash)
	
	// 트랜잭션들 추가
	for _, tx := range transactions {
		builder.AddTransaction(tx)
	}
	
	block := builder.Build()
	
	// 자신의 체인에 추가
	if n.validateAndAddBlock(block) {
		fmt.Printf("Node %s: Mined block #%d with %d transactions\n", 
			n.ID, block.Number, len(transactions))
		return block
	}
	
	return nil
}

// Tendermint 메시지 핸들러들

// handleTendermintProposal 텐더민트 제안 처리
func (n *Node) handleTendermintProposal(msg *Message) {
	// TendermintNode로 타입 캐스팅이 필요한 경우 처리
	if tn, ok := interface{}(n).(*TendermintNode); ok {
		proposalData, ok := msg.Data.(map[string]interface{})
		if !ok {
			log.Printf("Invalid proposal data")
			return
		}
		
		// JSON을 통한 변환
		proposalJSON, _ := json.Marshal(proposalData)
		var proposal Proposal
		if err := json.Unmarshal(proposalJSON, &proposal); err != nil {
			log.Printf("Error unmarshaling proposal: %v", err)
			return
		}
		
		// 제안 채널로 전송
		select {
		case tn.proposalChan <- &proposal:
		default:
			log.Printf("Proposal channel full, dropping proposal")
		}
	} else {
		log.Printf("Node is not a TendermintNode, ignoring proposal")
	}
}

// handleTendermintVote 텐더민트 투표 처리
func (n *Node) handleTendermintVote(msg *Message) {
	if tn, ok := interface{}(n).(*TendermintNode); ok {
		voteData, ok := msg.Data.(map[string]interface{})
		if !ok {
			log.Printf("Invalid vote data")
			return
		}
		
		// JSON을 통한 변환
		voteJSON, _ := json.Marshal(voteData)
		var vote Vote
		if err := json.Unmarshal(voteJSON, &vote); err != nil {
			log.Printf("Error unmarshaling vote: %v", err)
			return
		}
		
		// 투표 채널로 전송
		select {
		case tn.voteChan <- &vote:
		default:
			log.Printf("Vote channel full, dropping vote")
		}
	} else {
		log.Printf("Node is not a TendermintNode, ignoring vote")
	}
}

// handleValidatorInfo 검증자 정보 처리
func (n *Node) handleValidatorInfo(msg *Message) {
	validatorData, ok := msg.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid validator data")
		return
	}
	
	fmt.Printf("Node %s: Received validator info from %s\n", n.ID, msg.From)
	// 검증자 정보 처리 로직
	_ = validatorData
}

// handleStakingEvent 스테이킹 이벤트 처리
func (n *Node) handleStakingEvent(msg *Message) {
	stakingData, ok := msg.Data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid staking event data")
		return
	}
	
	fmt.Printf("Node %s: Received staking event from %s\n", n.ID, msg.From)
	// 스테이킹 이벤트 처리 로직
	_ = stakingData
}

// BroadcastValidatorInfo 검증자 정보 브로드캐스트
func (n *Node) BroadcastValidatorInfo(validator *Validator) {
	msg := Message{
		Type:      "validator_info",
		From:      n.ID,
		Data:      validator,
		Timestamp: uint64(time.Now().Unix()),
	}
	
	n.broadcastToAll(&msg)
	fmt.Printf("Node %s: Broadcasted validator info to %d peers\n", 
		n.ID, len(n.Peers))
}

// BroadcastStakingEvent 스테이킹 이벤트 브로드캐스트
func (n *Node) BroadcastStakingEvent(event interface{}) {
	msg := Message{
		Type:      "staking_event", 
		From:      n.ID,
		Data:      event,
		Timestamp: uint64(time.Now().Unix()),
	}
	
	n.broadcastToAll(&msg)
	fmt.Printf("Node %s: Broadcasted staking event to %d peers\n",
		n.ID, len(n.Peers))
}