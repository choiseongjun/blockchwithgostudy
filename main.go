package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

// Hash represents a 32-byte hash
type Hash [32]byte

func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h Hash) String() string {
	return h.Hex()
}

// Keccak256 computes keccak256 hash
func Keccak256(data ...[]byte) Hash {
	hasher := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hasher.Write(d)
	}
	var result Hash
	copy(result[:], hasher.Sum(nil))
	return result
}

// Transaction represents an Ethereum-like transaction with digital signature
type Transaction struct {
	From      string   `json:"from"`      // Address string (derived from public key)
	To        string   `json:"to"`
	Value     *big.Int `json:"value"`
	Nonce     uint64   `json:"nonce"`
	GasPrice  *big.Int `json:"gasPrice"`
	GasLimit  uint64   `json:"gasLimit"`
	Data      []byte   `json:"data"`
	Signature string   `json:"signature"` // ECDSA signature in hex
	PublicKey string   `json:"publicKey"` // Public key in hex
}

// GetSigningData returns the data to be signed (without signature fields)
func (tx *Transaction) GetSigningData() []byte {
	data := fmt.Sprintf("%s%s%s%d%s%d",
		tx.From, tx.To, tx.Value.String(), tx.Nonce,
		tx.GasPrice.String(), tx.GasLimit)
	combined := append([]byte(data), tx.Data...)
	return combined
}

// Hash returns the hash of the transaction (including signature for uniqueness)
func (tx *Transaction) Hash() Hash {
	signingData := tx.GetSigningData()
	if tx.Signature != "" {
		combined := append(signingData, []byte(tx.Signature)...)
		return Keccak256(combined)
	}
	return Keccak256(signingData)
}

// VerifySignature verifies the transaction signature
func (tx *Transaction) VerifySignature() bool {
	if tx.Signature == "" || tx.PublicKey == "" {
		return false
	}

	// Parse signature
	signature, err := SignatureFromHex(tx.Signature)
	if err != nil {
		return false
	}

	// Parse public key
	pubKey, err := PublicKeyFromHex(tx.PublicKey)
	if err != nil {
		return false
	}

	// Verify that the From address matches the public key
	expectedAddress := pubKey.ToAddress()
	if string(expectedAddress) != tx.From {
		return false
	}

	// Verify signature
	signingData := tx.GetSigningData()
	return pubKey.Verify(signingData, signature)
}

// GetSender returns the sender address derived from the signature
func (tx *Transaction) GetSender() (Address, error) {
	if tx.PublicKey == "" {
		return "", fmt.Errorf("no public key in transaction")
	}

	pubKey, err := PublicKeyFromHex(tx.PublicKey)
	if err != nil {
		return "", err
	}

	return pubKey.ToAddress(), nil
}

// Receipt represents a transaction receipt
type Receipt struct {
	TxHash            Hash   `json:"transactionHash"`
	Status            uint64 `json:"status"` // 1 = success, 0 = failure
	GasUsed           uint64 `json:"gasUsed"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed"`
	Logs              []Log  `json:"logs"`
}

// Hash returns the hash of the receipt
func (r *Receipt) Hash() Hash {
	data := fmt.Sprintf("%s%d%d%d%d",
		r.TxHash.Hex(), r.Status, r.GasUsed, r.CumulativeGasUsed, len(r.Logs))
	return Keccak256([]byte(data))
}

// Log represents an event log
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    []byte   `json:"data"`
}

// Account represents an Ethereum account
type Account struct {
	Address     string   `json:"address"`
	Balance     *big.Int `json:"balance"`
	Nonce       uint64   `json:"nonce"`
	CodeHash    Hash     `json:"codeHash"`
	StorageRoot Hash     `json:"storageRoot"`
}

// Hash returns the hash of the account
func (acc *Account) Hash() Hash {
	data := fmt.Sprintf("%s%s%d%s%s",
		acc.Address, acc.Balance.String(), acc.Nonce,
		acc.CodeHash.Hex(), acc.StorageRoot.Hex())
	return Keccak256([]byte(data))
}

// Block represents an Ethereum-like block
type Block struct {
	Number       uint64         `json:"number"`
	ParentHash   Hash           `json:"parentHash"`
	Timestamp    uint64         `json:"timestamp"`
	Transactions []*Transaction `json:"transactions"`
	Receipts     []*Receipt     `json:"receipts"`
	Accounts     []*Account     `json:"accounts"`

	// Merkle roots
	TxRoot      Hash `json:"transactionsRoot"`
	ReceiptRoot Hash `json:"receiptsRoot"`
	StateRoot   Hash `json:"stateRoot"`
}

// MerkleTree represents a merkle tree
type MerkleTree struct {
	leaves []Hash
	nodes  map[string]Hash // level_index -> hash
	root   Hash
	height int
}

// NewMerkleTree creates a new merkle tree
func NewMerkleTree(leaves []Hash) *MerkleTree {
	tree := &MerkleTree{
		leaves: leaves,
		nodes:  make(map[string]Hash),
	}

	if len(leaves) == 0 {
		tree.root = Keccak256([]byte{})
		return tree
	}

	tree.height = tree.calculateHeight()
	tree.root = tree.computeRoot()
	return tree
}

func (mt *MerkleTree) calculateHeight() int {
	if len(mt.leaves) == 0 {
		return 0
	}
	height := 0
	size := len(mt.leaves)
	for (1 << height) < size {
		height++
	}
	return height
}

func (mt *MerkleTree) getNodeKey(level, index int) string {
	return fmt.Sprintf("%d_%d", level, index)
}

func (mt *MerkleTree) getHashAtLevel(level, index int) Hash {
	key := mt.getNodeKey(level, index)
	if cached, exists := mt.nodes[key]; exists {
		return cached
	}

	var hash Hash
	if level == 0 {
		// Leaf level
		if index < len(mt.leaves) {
			hash = mt.leaves[index]
		} else {
			hash = Hash{} // Empty hash
		}
	} else {
		// Internal node
		leftChild := mt.getHashAtLevel(level-1, index*2)
		rightChild := mt.getHashAtLevel(level-1, index*2+1)
		hash = Keccak256(leftChild[:], rightChild[:])
	}

	mt.nodes[key] = hash
	return hash
}

func (mt *MerkleTree) computeRoot() Hash {
	if len(mt.leaves) == 0 {
		return Keccak256([]byte{})
	}
	return mt.getHashAtLevel(mt.height, 0)
}

// GetRoot returns the merkle root
func (mt *MerkleTree) GetRoot() Hash {
	return mt.root
}

// GenerateProof generates merkle proof for leaf at given index
func (mt *MerkleTree) GenerateProof(index int) ([]Hash, error) {
	if index >= len(mt.leaves) {
		return nil, fmt.Errorf("index %d out of range", index)
	}

	proof := make([]Hash, 0, mt.height)
	currentIndex := index

	for level := 0; level < mt.height; level++ {
		siblingIndex := currentIndex ^ 1 // XOR to get sibling
		siblingHash := mt.getHashAtLevel(level, siblingIndex)
		proof = append(proof, siblingHash)
		currentIndex /= 2
	}

	return proof, nil
}

// VerifyProof verifies a merkle proof
func (mt *MerkleTree) VerifyProof(leaf Hash, index int, proof []Hash) bool {
	if index >= len(mt.leaves) {
		return false
	}

	currentHash := leaf
	currentIndex := index

	for _, sibling := range proof {
		if currentIndex%2 == 0 {
			currentHash = Keccak256(currentHash[:], sibling[:])
		} else {
			currentHash = Keccak256(sibling[:], currentHash[:])
		}
		currentIndex /= 2
	}

	return bytes.Equal(currentHash[:], mt.root[:])
}

// BlockBuilder helps build blocks with merkle trees
type BlockBuilder struct {
	number       uint64
	parentHash   Hash
	transactions []*Transaction
	accounts     map[string]*Account
	receipts     []*Receipt
	gasUsed      uint64
}

// NewBlockBuilder creates a new block builder
func NewBlockBuilder(number uint64, parentHash Hash) *BlockBuilder {
	return &BlockBuilder{
		number:     number,
		parentHash: parentHash,
		accounts:   make(map[string]*Account),
	}
}

// AddTransaction adds a transaction to the block
func (bb *BlockBuilder) AddTransaction(tx *Transaction) error {
	// Execute transaction and update state
	receipt, err := bb.executeTransaction(tx)
	if err != nil {
		return err
	}

	bb.transactions = append(bb.transactions, tx)
	bb.receipts = append(bb.receipts, receipt)
	bb.gasUsed += receipt.GasUsed

	return nil
}

func (bb *BlockBuilder) executeTransaction(tx *Transaction) (*Receipt, error) {
	// 1. Verify digital signature first
	if !tx.VerifySignature() {
		return &Receipt{
			TxHash:            tx.Hash(),
			Status:            0, // Failed - invalid signature
			GasUsed:           0,  // No gas used for invalid signature
			CumulativeGasUsed: bb.gasUsed,
			Logs:              []Log{},
		}, fmt.Errorf("invalid transaction signature")
	}

	// 2. Get or create accounts
	fromAccount := bb.getOrCreateAccount(tx.From)
	toAccount := bb.getOrCreateAccount(tx.To)

	// 3. Calculate total cost (value + gas fees)
	totalGasCost := new(big.Int).Mul(tx.GasPrice, big.NewInt(int64(tx.GasLimit)))
	totalCost := new(big.Int).Add(tx.Value, totalGasCost)

	// 4. Check balance (value + gas fees)
	if fromAccount.Balance.Cmp(totalCost) < 0 {
		return &Receipt{
			TxHash:            tx.Hash(),
			Status:            0, // Failed - insufficient funds
			GasUsed:           21000,
			CumulativeGasUsed: bb.gasUsed + 21000,
			Logs:              []Log{},
		}, fmt.Errorf("insufficient funds: need %s, have %s", totalCost.String(), fromAccount.Balance.String())
	}

	// 5. Check nonce
	if fromAccount.Nonce != tx.Nonce {
		return &Receipt{
			TxHash:            tx.Hash(),
			Status:            0, // Failed - invalid nonce
			GasUsed:           21000,
			CumulativeGasUsed: bb.gasUsed + 21000,
			Logs:              []Log{},
		}, fmt.Errorf("invalid nonce: expected %d, got %d", fromAccount.Nonce, tx.Nonce)
	}

	// 6. Execute transfer
	fromAccount.Balance.Sub(fromAccount.Balance, totalCost) // Deduct value + gas
	fromAccount.Nonce++
	toAccount.Balance.Add(toAccount.Balance, tx.Value) // Only add value to recipient

	// Create successful receipt
	receipt := &Receipt{
		TxHash:            tx.Hash(),
		Status:            1, // Success
		GasUsed:           21000,
		CumulativeGasUsed: bb.gasUsed + 21000,
		Logs:              []Log{},
	}

	return receipt, nil
}

func (bb *BlockBuilder) getOrCreateAccount(address string) *Account {
	if account, exists := bb.accounts[address]; exists {
		return account
	}

	account := &Account{
		Address:     address,
		Balance:     big.NewInt(1000), // Default balance
		Nonce:       0,
		CodeHash:    Hash{},
		StorageRoot: Hash{},
	}
	bb.accounts[address] = account
	return account
}

// Build creates the final block with all merkle roots
func (bb *BlockBuilder) Build() *Block {
	// Calculate transaction merkle root
	txHashes := make([]Hash, len(bb.transactions))
	for i, tx := range bb.transactions {
		txHashes[i] = tx.Hash()
	}
	txTree := NewMerkleTree(txHashes)

	// Calculate receipt merkle root
	receiptHashes := make([]Hash, len(bb.receipts))
	for i, receipt := range bb.receipts {
		receiptHashes[i] = receipt.Hash()
	}
	receiptTree := NewMerkleTree(receiptHashes)

	// Calculate state merkle root
	accounts := make([]*Account, 0, len(bb.accounts))
	for _, account := range bb.accounts {
		accounts = append(accounts, account)
	}
	// Sort accounts by address for deterministic ordering
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Address < accounts[j].Address
	})

	stateHashes := make([]Hash, len(accounts))
	for i, account := range accounts {
		stateHashes[i] = account.Hash()
	}
	stateTree := NewMerkleTree(stateHashes)

	return &Block{
		Number:       bb.number,
		ParentHash:   bb.parentHash,
		Timestamp:    uint64(time.Now().Unix()),
		Transactions: bb.transactions,
		Receipts:     bb.receipts,
		Accounts:     accounts,
		TxRoot:       txTree.GetRoot(),
		ReceiptRoot:  receiptTree.GetRoot(),
		StateRoot:    stateTree.GetRoot(),
	}
}

// TransactionProof represents a proof that a transaction is included in a block
type TransactionProof struct {
	Transaction      *Transaction `json:"transaction"`
	TransactionIndex int          `json:"transactionIndex"`
	BlockNumber      uint64       `json:"blockNumber"`
	BlockTxRoot      Hash         `json:"blockTransactionRoot"`
	Proof            []string     `json:"proof"`
}

// LightClient represents a light client that only stores block headers
type LightClient struct {
	blockHeaders map[uint64]*BlockHeader
}

// BlockHeader represents a block header (without full transaction data)
type BlockHeader struct {
	Number      uint64 `json:"number"`
	ParentHash  Hash   `json:"parentHash"`
	Timestamp   uint64 `json:"timestamp"`
	TxRoot      Hash   `json:"transactionsRoot"`
	ReceiptRoot Hash   `json:"receiptsRoot"`
	StateRoot   Hash   `json:"stateRoot"`
	TxCount     int    `json:"transactionCount"`
}

// NewLightClient creates a new light client
func NewLightClient() *LightClient {
	return &LightClient{
		blockHeaders: make(map[uint64]*BlockHeader),
	}
}

// StoreBlockHeader stores a block header
func (lc *LightClient) StoreBlockHeader(header *BlockHeader) {
	lc.blockHeaders[header.Number] = header
}

// VerifyTransactionInclusion verifies that a transaction is included in a block
func (lc *LightClient) VerifyTransactionInclusion(proof *TransactionProof) (bool, error) {
	// Get block header
	header, exists := lc.blockHeaders[proof.BlockNumber]
	if !exists {
		return false, fmt.Errorf("block header not found for block %d", proof.BlockNumber)
	}

	// Verify that the provided tx root matches the block header
	if !bytes.Equal(proof.BlockTxRoot[:], header.TxRoot[:]) {
		return false, fmt.Errorf("transaction root mismatch")
	}

	// Convert proof strings to hashes
	proofHashes := make([]Hash, len(proof.Proof))
	for i, p := range proof.Proof {
		proofBytes, err := hex.DecodeString(p[2:]) // Remove 0x prefix
		if err != nil {
			return false, fmt.Errorf("invalid proof format: %v", err)
		}
		copy(proofHashes[i][:], proofBytes)
	}

	// Create a temporary merkle tree for verification
	// We need to know the total number of transactions to verify properly
	leaves := make([]Hash, header.TxCount)
	// We only know one leaf (the transaction we're verifying)
	leaves[proof.TransactionIndex] = proof.Transaction.Hash()

	// For proper verification, we would need all transaction hashes or use a different approach
	// Here we'll verify the proof manually
	return lc.verifyMerkleProof(
		proof.Transaction.Hash(),
		proof.TransactionIndex,
		proofHashes,
		proof.BlockTxRoot,
	), nil
}

func (lc *LightClient) verifyMerkleProof(leaf Hash, index int, proof []Hash, expectedRoot Hash) bool {
	currentHash := leaf
	currentIndex := index

	for _, sibling := range proof {
		if currentIndex%2 == 0 {
			currentHash = Keccak256(currentHash[:], sibling[:])
		} else {
			currentHash = Keccak256(sibling[:], currentHash[:])
		}
		currentIndex /= 2
	}

	return bytes.Equal(currentHash[:], expectedRoot[:])
}

// FullNode represents a full node that stores complete blocks
type FullNode struct {
	blocks map[uint64]*Block
}

// NewFullNode creates a new full node
func NewFullNode() *FullNode {
	return &FullNode{
		blocks: make(map[uint64]*Block),
	}
}

// StoreBlock stores a complete block
func (fn *FullNode) StoreBlock(block *Block) {
	fn.blocks[block.Number] = block
}

// GenerateTransactionProof generates a proof that a transaction is included in a block
func (fn *FullNode) GenerateTransactionProof(blockNumber uint64, txIndex int) (*TransactionProof, error) {
	block, exists := fn.blocks[blockNumber]
	if !exists {
		return nil, fmt.Errorf("block %d not found", blockNumber)
	}

	if txIndex >= len(block.Transactions) {
		return nil, fmt.Errorf("transaction index %d out of range", txIndex)
	}

	// Build merkle tree for transactions
	txHashes := make([]Hash, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.Hash()
	}
	txTree := NewMerkleTree(txHashes)

	// Generate proof
	proof, err := txTree.GenerateProof(txIndex)
	if err != nil {
		return nil, err
	}

	// Convert proof to strings
	proofStrings := make([]string, len(proof))
	for i, p := range proof {
		proofStrings[i] = p.Hex()
	}

	return &TransactionProof{
		Transaction:      block.Transactions[txIndex],
		TransactionIndex: txIndex,
		BlockNumber:      blockNumber,
		BlockTxRoot:      block.TxRoot,
		Proof:            proofStrings,
	}, nil
}

// GetBlockHeader returns just the header of a block
func (fn *FullNode) GetBlockHeader(blockNumber uint64) *BlockHeader {
	block, exists := fn.blocks[blockNumber]
	if !exists {
		return nil
	}

	return &BlockHeader{
		Number:      block.Number,
		ParentHash:  block.ParentHash,
		Timestamp:   block.Timestamp,
		TxRoot:      block.TxRoot,
		ReceiptRoot: block.ReceiptRoot,
		StateRoot:   block.StateRoot,
		TxCount:     len(block.Transactions),
	}
}

func main() {
	fmt.Println("블록체인 프로그램을 시작합니다...")
	fmt.Println("1: 기본 블록체인 데모")
	fmt.Println("2: P2P 네트워크 데모")
	fmt.Println("3: 간단한 네트워크 테스트")
	fmt.Println("4: 디지털 서명 데모")
	
	var choice int
	fmt.Print("선택하세요 (1-4): ")
	fmt.Scanf("%d", &choice)
	
	switch choice {
	case 1:
		runBasicDemo()
	case 2:
		NetworkDemo()
	case 3:
		SimpleNetworkTest()
	case 4:
		DigitalSignatureDemo()
	default:
		fmt.Println("잘못된 선택입니다. 기본 데모를 실행합니다.")
		runBasicDemo()
	}
}

func runBasicDemo() {
	fmt.Println("=== 기본 블록체인 머클트리 데모 ===\n")

	// 1. 블록 생성
	fmt.Println("1. 블록 생성 중...")
	builder := NewBlockBuilder(100, Hash{})

	// 초기 계정 설정
	builder.getOrCreateAccount("alice").Balance = big.NewInt(1000)
	builder.getOrCreateAccount("bob").Balance = big.NewInt(500)
	builder.getOrCreateAccount("charlie").Balance = big.NewInt(200)

	// 트랜잭션들 추가
	transactions := []*Transaction{
		{
			From:     "alice",
			To:       "bob",
			Value:    big.NewInt(100),
			Nonce:    0,
			GasPrice: big.NewInt(20000000000),
			GasLimit: 21000,
			Data:     []byte{},
		},
		{
			From:     "bob",
			To:       "charlie",
			Value:    big.NewInt(50),
			Nonce:    0,
			GasPrice: big.NewInt(25000000000),
			GasLimit: 21000,
			Data:     []byte{},
		},
		{
			From:     "charlie",
			To:       "alice",
			Value:    big.NewInt(25),
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			GasLimit: 21000,
			Data:     []byte{},
		},
	}

	for _, tx := range transactions {
		err := builder.AddTransaction(tx)
		if err != nil {
			log.Printf("Failed to add transaction: %v", err)
		}
	}

	// 블록 빌드
	block := builder.Build()

	fmt.Printf("블록 #%d 생성 완료\n", block.Number)
	fmt.Printf("  트랜잭션 개수: %d\n", len(block.Transactions))
	fmt.Printf("  트랜잭션 루트: %s\n", block.TxRoot.Hex())
	fmt.Printf("  Receipt 루트: %s\n", block.ReceiptRoot.Hex())
	fmt.Printf("  상태 루트: %s\n", block.StateRoot.Hex())

	// 2. 풀 노드 생성 및 블록 저장
	fmt.Println("\n2. 풀 노드에 블록 저장...")
	fullNode := NewFullNode()
	fullNode.StoreBlock(block)

	// 3. 트랜잭션 포함 증명 생성
	fmt.Println("\n3. 트랜잭션 포함 증명 생성...")
	proof, err := fullNode.GenerateTransactionProof(100, 1) // 두 번째 트랜잭션
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("트랜잭션 증명 생성 완료:\n")
	fmt.Printf("  트랜잭션: %s -> %s, 금액: %s\n",
		proof.Transaction.From,
		proof.Transaction.To,
		proof.Transaction.Value.String())
	fmt.Printf("  증명 길이: %d\n", len(proof.Proof))
	fmt.Printf("  블록 번호: %d\n", proof.BlockNumber)

	// 4. 라이트 클라이언트 생성 및 검증
	fmt.Println("\n4. 라이트 클라이언트로 검증...")
	lightClient := NewLightClient()

	// 블록 헤더만 저장 (실제로는 네트워크에서 받음)
	header := fullNode.GetBlockHeader(100)
	lightClient.StoreBlockHeader(header)

	// 증명 검증
	isValid, err := lightClient.VerifyTransactionInclusion(proof)
	if err != nil {
		log.Printf("검증 에러: %v", err)
	} else {
		fmt.Printf("라이트 클라이언트 검증 결과: %t\n", isValid)
	}

	// 5. 데이터 효율성 비교
	fmt.Println("\n5. 데이터 효율성 비교...")

	// 전체 블록 크기
	blockData, _ := json.Marshal(block)
	fullBlockSize := len(blockData)

	// 증명 크기
	proofData, _ := json.Marshal(proof)
	proofSize := len(proofData)

	// 헤더 크기
	headerData, _ := json.Marshal(header)
	headerSize := len(headerData)

	fmt.Printf("전체 블록 크기: %d bytes\n", fullBlockSize)
	fmt.Printf("헤더 + 증명 크기: %d bytes\n", headerSize+proofSize)
	fmt.Printf("데이터 절약률: %.1f%%\n",
		float64(fullBlockSize-headerSize-proofSize)/float64(fullBlockSize)*100)

	// 6. 잘못된 증명 테스트
	fmt.Println("\n6. 잘못된 증명 테스트...")

	// 증명 데이터 조작
	fakeProof := *proof
	if len(fakeProof.Proof) > 0 {
		fakeProof.Proof[0] = "0x" + strings.Repeat("ff", 32) // 첫 번째 증명 해시 조작
	}

	fakeIsValid, err := lightClient.VerifyTransactionInclusion(&fakeProof)
	if err != nil {
		fmt.Printf("조작된 증명 검증 에러: %v\n", err)
	} else {
		fmt.Printf("조작된 증명 검증 결과: %t (false여야 정상)\n", fakeIsValid)
	}

	// 7. 성능 테스트
	fmt.Println("\n7. 성능 측정...")

	start := time.Now()
	for i := 0; i < 1000; i++ {
		txHashes := make([]Hash, 1000)
		for j := range txHashes {
			data := fmt.Sprintf("tx_%d_%d", i, j)
			txHashes[j] = Keccak256([]byte(data))
		}
		tree := NewMerkleTree(txHashes)
		tree.GenerateProof(500)
	}
	duration := time.Since(start)

	fmt.Printf("1000개 트랜잭션 × 1000번 증명 생성: %v\n", duration)
	fmt.Printf("평균 증명 생성 시간: %v\n", duration/1000)
}

// NetworkDemo demonstrates P2P blockchain network
func NetworkDemo() {
	fmt.Println("=== P2P 블록체인 네트워크 데모 ===\n")

	// 1. 3개 노드 생성
	fmt.Println("1. 노드들 생성 중...")
	node1 := NewNode("Alice", "localhost", 8001)
	node2 := NewNode("Bob", "localhost", 8002)
	node3 := NewNode("Charlie", "localhost", 8003)

	// 2. 노드들 시작
	fmt.Println("2. 노드들 시작...")
	node1.Start()
	node2.Start()
	node3.Start()

	// 잠시 대기 (서버 시작 시간)
	time.Sleep(100 * time.Millisecond)

	// 3. 노드들 연결 (P2P 네트워크 형성)
	fmt.Println("3. P2P 네트워크 형성...")
	node1.ConnectToPeer("localhost:8002") // Alice -> Bob
	node2.ConnectToPeer("localhost:8003") // Bob -> Charlie
	node3.ConnectToPeer("localhost:8001") // Charlie -> Alice

	time.Sleep(200 * time.Millisecond)

	// 4. 제네시스 블록 생성 (Alice가 생성)
	fmt.Println("4. 제네시스 블록 생성...")
	genesisBuilder := NewBlockBuilder(0, Hash{})
	genesisBuilder.getOrCreateAccount("alice").Balance = big.NewInt(1000)
	genesisBuilder.getOrCreateAccount("bob").Balance = big.NewInt(500)
	genesisBuilder.getOrCreateAccount("charlie").Balance = big.NewInt(300)
	
	genesisBlock := genesisBuilder.Build()
	
	// 모든 노드에 제네시스 블록 추가
	node1.validateAndAddBlock(genesisBlock)
	node2.validateAndAddBlock(genesisBlock)
	node3.validateAndAddBlock(genesisBlock)

	// 5. 트랜잭션 생성 및 브로드캐스트
	fmt.Println("5. 트랜잭션 생성 및 네트워크 전파...")
	
	tx1 := &Transaction{
		From:     "alice",
		To:       "bob",
		Value:    big.NewInt(100),
		Nonce:    0,
		GasPrice: big.NewInt(20000000000),
		GasLimit: 21000,
		Data:     []byte{},
	}

	tx2 := &Transaction{
		From:     "bob",
		To:       "charlie",
		Value:    big.NewInt(50),
		Nonce:    0,
		GasPrice: big.NewInt(25000000000),
		GasLimit: 21000,
		Data:     []byte{},
	}

	// Alice가 트랜잭션 브로드캐스트
	node1.BroadcastTransaction(tx1)
	time.Sleep(100 * time.Millisecond)
	
	// Bob이 트랜잭션 브로드캐스트
	node2.BroadcastTransaction(tx2)
	time.Sleep(100 * time.Millisecond)

	// 6. 멤풀 상태 확인
	fmt.Println("6. 각 노드의 멤풀 상태:")
	fmt.Printf("   Alice 멤풀: %d 트랜잭션\n", node1.GetMempoolSize())
	fmt.Printf("   Bob 멤풀: %d 트랜잭션\n", node2.GetMempoolSize())
	fmt.Printf("   Charlie 멤풀: %d 트랜잭션\n", node3.GetMempoolSize())

	// 7. Bob이 블록 마이닝
	fmt.Println("7. Bob이 블록 마이닝...")
	newBlock := node2.MineBlock()
	if newBlock != nil {
		// 네트워크에 브로드캐스트
		node2.BroadcastBlock(newBlock)
		time.Sleep(200 * time.Millisecond)
	}

	// 8. 모든 노드의 블록체인 상태 확인
	fmt.Println("8. 네트워크 동기화 결과:")
	fmt.Printf("   Alice 블록체인 길이: %d\n", node1.GetBlockchainLength())
	fmt.Printf("   Bob 블록체인 길이: %d\n", node2.GetBlockchainLength())
	fmt.Printf("   Charlie 블록체인 길이: %d\n", node3.GetBlockchainLength())

	// 9. 추가 트랜잭션으로 네트워크 테스트
	fmt.Println("9. 추가 트랜잭션 테스트...")
	
	tx3 := &Transaction{
		From:     "charlie",
		To:       "alice",
		Value:    big.NewInt(25),
		Nonce:    0,
		GasPrice: big.NewInt(30000000000),
		GasLimit: 21000,
		Data:     []byte{},
	}

	// Charlie가 브로드캐스트
	node3.BroadcastTransaction(tx3)
	time.Sleep(100 * time.Millisecond)

	// Alice가 마이닝
	fmt.Println("10. Alice가 블록 마이닝...")
	aliceBlock := node1.MineBlock()
	if aliceBlock != nil {
		node1.BroadcastBlock(aliceBlock)
		time.Sleep(200 * time.Millisecond)
	}

	// 11. 최종 상태 확인
	fmt.Println("11. 최종 네트워크 상태:")
	fmt.Printf("   Alice: %d 블록, %d 멤풀, %d 피어\n", 
		node1.GetBlockchainLength(), node1.GetMempoolSize(), len(node1.Peers))
	fmt.Printf("   Bob: %d 블록, %d 멤풀, %d 피어\n", 
		node2.GetBlockchainLength(), node2.GetMempoolSize(), len(node2.Peers))
	fmt.Printf("   Charlie: %d 블록, %d 멤풀, %d 피어\n", 
		node3.GetBlockchainLength(), node3.GetMempoolSize(), len(node3.Peers))

	// 12. 성능 테스트
	fmt.Println("12. 네트워크 성능 테스트...")
	start := time.Now()
	
	// 10개 트랜잭션 동시 전송
	for i := 0; i < 10; i++ {
		tx := &Transaction{
			From:     "alice",
			To:       "bob",
			Value:    big.NewInt(int64(i + 1)),
			Nonce:    uint64(i + 1),
			GasPrice: big.NewInt(20000000000),
			GasLimit: 21000,
			Data:     []byte(fmt.Sprintf("tx_%d", i)),
		}
		node1.BroadcastTransaction(tx)
	}
	
	// 블록 마이닝
	testBlock := node2.MineBlock()
	if testBlock != nil {
		node2.BroadcastBlock(testBlock)
	}
	
	duration := time.Since(start)
	fmt.Printf("   10개 트랜잭션 처리 시간: %v\n", duration)

	// 13. 정리
	fmt.Println("13. 노드들 종료...")
	time.Sleep(500 * time.Millisecond)
	node1.Stop()
	node2.Stop()
	node3.Stop()

	fmt.Println("=== P2P 네트워크 데모 완료 ===")
}

// SimpleNetworkTest tests basic network functionality
func SimpleNetworkTest() {
	fmt.Println("=== 간단한 네트워크 테스트 ===\n")

	// 2개 노드로 간단한 테스트
	nodeA := NewNode("NodeA", "localhost", 9001)
	nodeB := NewNode("NodeB", "localhost", 9002)

	nodeA.Start()
	nodeB.Start()

	time.Sleep(100 * time.Millisecond)

	// 연결
	nodeA.ConnectToPeer("localhost:9002")
	time.Sleep(100 * time.Millisecond)

	// 트랜잭션 테스트
	tx := &Transaction{
		From:     "test1",
		To:       "test2",
		Value:    big.NewInt(100),
		Nonce:    0,
		GasPrice: big.NewInt(1000000000),
		GasLimit: 21000,
		Data:     []byte("test"),
	}

	fmt.Println("NodeA가 트랜잭션 브로드캐스트...")
	nodeA.BroadcastTransaction(tx)

	time.Sleep(200 * time.Millisecond)

	fmt.Printf("NodeA 멤풀: %d\n", nodeA.GetMempoolSize())
	fmt.Printf("NodeB 멤풀: %d\n", nodeB.GetMempoolSize())

	nodeA.Stop()
	nodeB.Stop()

	fmt.Println("=== 간단한 테스트 완료 ===")
}

// DigitalSignatureDemo demonstrates digital signature functionality
func DigitalSignatureDemo() {
	fmt.Println("=== 디지털 서명 블록체인 데모 ===\n")

	// 1. 지갑 생성
	fmt.Println("1. 지갑 생성 중...")
	keyManager := NewKeyManager()
	
	aliceWallet, _ := keyManager.CreateWallet("alice")
	bobWallet, _ := keyManager.CreateWallet("bob")
	charlieWallet, _ := keyManager.CreateWallet("charlie")

	fmt.Printf("Alice 지갑: %s\n", aliceWallet.Address)
	fmt.Printf("Bob 지갑: %s\n", bobWallet.Address)
	fmt.Printf("Charlie 지갑: %s\n", charlieWallet.Address)

	// 2. 블록 빌더 생성 및 초기 잔액 설정
	fmt.Println("\n2. 초기 계정 설정...")
	builder := NewBlockBuilder(1, Hash{})
	
	// 지갑 주소로 계정 생성
	aliceAccount := builder.getOrCreateAccount(string(aliceWallet.Address))
	bobAccount := builder.getOrCreateAccount(string(bobWallet.Address))
	charlieAccount := builder.getOrCreateAccount(string(charlieWallet.Address))
	
	aliceAccount.Balance = big.NewInt(1000000000000000000) // 1 ETH in wei
	bobAccount.Balance = big.NewInt(500000000000000000)   // 0.5 ETH
	charlieAccount.Balance = big.NewInt(200000000000000000) // 0.2 ETH

	fmt.Printf("Alice 초기 잔액: %s\n", aliceAccount.Balance.String())
	fmt.Printf("Bob 초기 잔액: %s\n", bobAccount.Balance.String())
	fmt.Printf("Charlie 초기 잔액: %s\n", charlieAccount.Balance.String())

	// 3. 서명된 트랜잭션 생성
	fmt.Println("\n3. 서명된 트랜잭션 생성...")
	
	// Alice -> Bob 0.1 ETH 전송
	tx1 := &Transaction{
		From:     string(aliceWallet.Address),
		To:       string(bobWallet.Address),
		Value:    big.NewInt(100000000000000000), // 0.1 ETH
		Nonce:    0,
		GasPrice: big.NewInt(20000000000),
		GasLimit: 21000,
		Data:     []byte{},
	}
	
	err := aliceWallet.SignTransaction(tx1)
	if err != nil {
		fmt.Printf("Alice 트랜잭션 서명 실패: %v\n", err)
		return
	}
	fmt.Println("✓ Alice가 트랜잭션에 서명 완료")

	// Bob -> Charlie 0.05 ETH 전송 
	tx2 := &Transaction{
		From:     string(bobWallet.Address),
		To:       string(charlieWallet.Address),
		Value:    big.NewInt(50000000000000000), // 0.05 ETH
		Nonce:    0,
		GasPrice: big.NewInt(25000000000),
		GasLimit: 21000,
		Data:     []byte{},
	}
	
	err = bobWallet.SignTransaction(tx2)
	if err != nil {
		fmt.Printf("Bob 트랜잭션 서명 실패: %v\n", err)
		return
	}
	fmt.Println("✓ Bob이 트랜잭션에 서명 완료")

	// 4. 서명 검증 테스트
	fmt.Println("\n4. 서명 검증...")
	fmt.Printf("Alice 트랜잭션 서명 유효: %t\n", tx1.VerifySignature())
	fmt.Printf("Bob 트랜잭션 서명 유효: %t\n", tx2.VerifySignature())

	// 5. 가짜 트랜잭션 테스트 (서명 없이)
	fmt.Println("\n5. 가짜 트랜잭션 테스트...")
	fakeTx := &Transaction{
		From:     string(aliceWallet.Address),
		To:       string(bobWallet.Address),
		Value:    big.NewInt(500000000000000000), // 0.5 ETH (Alice가 서명하지 않은 거래)
		Nonce:    1,
		GasPrice: big.NewInt(20000000000),
		GasLimit: 21000,
		Data:     []byte{},
		// Signature와 PublicKey가 비어있음
	}
	fmt.Printf("가짜 트랜잭션 서명 유효: %t (false여야 정상)\n", fakeTx.VerifySignature())

	// 6. 트랜잭션 실행
	fmt.Println("\n6. 트랜잭션 실행...")
	
	receipt1, err := builder.executeTransaction(tx1)
	if err != nil {
		fmt.Printf("Alice 트랜잭션 실행 실패: %v\n", err)
	} else {
		fmt.Printf("Alice 트랜잭션 실행 결과: 상태=%d, 가스사용=%d\n", receipt1.Status, receipt1.GasUsed)
	}

	receipt2, err := builder.executeTransaction(tx2)
	if err != nil {
		fmt.Printf("Bob 트랜잭션 실행 실패: %v\n", err)
	} else {
		fmt.Printf("Bob 트랜잭션 실행 결과: 상태=%d, 가스사용=%d\n", receipt2.Status, receipt2.GasUsed)
	}

	// 가짜 트랜잭션 실행 시도
	fakeReceipt, err := builder.executeTransaction(fakeTx)
	if err != nil {
		fmt.Printf("가짜 트랜잭션 실행 실패 (정상): %v\n", err)
	} else {
		fmt.Printf("가짜 트랜잭션 실행 결과: 상태=%d (0이어야 정상)\n", fakeReceipt.Status)
	}

	// 7. 최종 잔액 확인
	fmt.Println("\n7. 최종 잔액 확인...")
	fmt.Printf("Alice 최종 잔액: %s\n", aliceAccount.Balance.String())
	fmt.Printf("Bob 최종 잔액: %s\n", bobAccount.Balance.String())
	fmt.Printf("Charlie 최종 잔액: %s\n", charlieAccount.Balance.String())

	// 8. 블록 생성
	fmt.Println("\n8. 블록 생성...")
	builder.AddTransaction(tx1)
	builder.AddTransaction(tx2)
	// 가짜 트랜잭션은 추가하지 않음 (서명 검증 실패로 거부됨)
	
	block := builder.Build()
	fmt.Printf("블록 #%d 생성 완료\n", block.Number)
	fmt.Printf("  포함된 트랜잭션: %d개\n", len(block.Transactions))
	fmt.Printf("  트랜잭션 루트: %s\n", block.TxRoot.Hex())

	// 9. 보안 데모
	fmt.Println("\n9. 보안 데모...")
	fmt.Println("디지털 서명의 보안 특징:")
	fmt.Println("✓ 신원 확인: 공개키로 발신자 검증")
	fmt.Println("✓ 무결성: 트랜잭션 변조 시 서명 검증 실패")
	fmt.Println("✓ 부인 방지: 개인키 소유자만 유효한 서명 생성 가능")
	fmt.Println("✓ 중복 방지: Nonce로 재전송 공격 방지")

	fmt.Println("\n=== 디지털 서명 데모 완료 ===")
}
