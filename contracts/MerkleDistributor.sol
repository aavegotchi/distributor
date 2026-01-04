// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title MerkleDistributor
/// @notice Distributes ETH via Merkle proof verification. 90-day claim period.
contract MerkleDistributor is Ownable, Pausable, ReentrancyGuard {
    uint256 public constant CLAIM_PERIOD = 90 days;
    uint256 public constant DEPOSIT_AMOUNT = 1036920000000700000000;
    bytes32 public constant MERKLE_ROOT =
        0xe07775359b09f65b178a4d87b31a37a0c67b6bdee74fe620edc57b3e7d87208b;

    address public immutable dao;
    bytes32 public merkleRoot;
    uint256 public claimStartTime;
    uint256 public totalDistribution;
    mapping(address => bool) public claimed;

    event ClaimsOpened(
        bytes32 indexed merkleRoot,
        uint256 totalAmount,
        uint256 claimStartTime
    );
    event Claimed(address indexed claimant, uint256 amount);
    event RemainingWithdrawn(address indexed dao, uint256 amount);

    error OnlyDAO();
    error ClaimsAlreadyOpened();
    error ClaimsNotOpened();
    error InvalidDepositAmount();
    error InvalidProof();
    error AlreadyClaimed();
    error ClaimPeriodExpired();
    error ClaimPeriodNotExpired();
    error TransferFailed();
    error InvalidDaoAddress();
    error InvalidMerkleRoot();

    modifier onlyDAO() {
        if (msg.sender != dao) revert OnlyDAO();
        _;
    }

    modifier onlyOwnerOrDAO() {
        if (msg.sender != owner() && msg.sender != dao) revert OnlyDAO();
        _;
    }

    constructor(address _dao, address _owner) Ownable(_owner) {
        if (_dao == address(0)) revert InvalidDaoAddress();
        dao = _dao;
    }

    function createDistributor(bytes32 _merkleRoot) external payable onlyDAO {
        //Sanity check: Prevent DAO from opening claims with an invalid merkle root
        if (_merkleRoot != MERKLE_ROOT) revert InvalidMerkleRoot();
        if (merkleRoot != bytes32(0)) revert ClaimsAlreadyOpened();

        //Sanity check: Prevent DAO from opening claims with an invalid deposit amount
        if (msg.value != DEPOSIT_AMOUNT) revert InvalidDepositAmount();

        merkleRoot = _merkleRoot;
        claimStartTime = block.timestamp;
        totalDistribution = msg.value;

        emit ClaimsOpened(_merkleRoot, msg.value, claimStartTime);
    }

    function claim(
        uint256 amount,
        bytes32[] calldata proof
    ) external whenNotPaused nonReentrant {
        if (claimStartTime == 0) revert ClaimsNotOpened();
        if (block.timestamp >= claimStartTime + CLAIM_PERIOD)
            revert ClaimPeriodExpired();
        if (claimed[msg.sender]) revert AlreadyClaimed();

        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(msg.sender, amount)))
        );
        if (!MerkleProof.verify(proof, merkleRoot, leaf)) revert InvalidProof();

        claimed[msg.sender] = true;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Claimed(msg.sender, amount);
    }

    /// @notice Withdraws remaining ETH after claim period expires. Can withdraw immediately if paused.
    function withdrawRemaining() external onlyDAO nonReentrant {
        if (claimStartTime == 0) revert ClaimsNotOpened();
        // Allow immediate withdrawal if contract is paused (emergency case)
        if (!paused() && block.timestamp < claimStartTime + CLAIM_PERIOD)
            revert ClaimPeriodNotExpired();

        uint256 remaining = address(this).balance;

        (bool success, ) = dao.call{value: remaining}("");
        if (!success) revert TransferFailed();

        emit RemainingWithdrawn(dao, remaining);
    }

    function pause() external onlyOwnerOrDAO {
        _pause();
    }

    function unpause() external onlyOwnerOrDAO {
        _unpause();
    }

    function isClaimPeriodActive() external view returns (bool) {
        return
            claimStartTime != 0 &&
            block.timestamp < claimStartTime + CLAIM_PERIOD;
    }

    function timeRemaining() external view returns (uint256) {
        if (claimStartTime == 0) return 0;
        uint256 endTime = claimStartTime + CLAIM_PERIOD;
        if (block.timestamp >= endTime) return 0;
        return endTime - block.timestamp;
    }

    function verifyClaim(
        address claimant,
        uint256 amount,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(claimant, amount)))
        );
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }
}
