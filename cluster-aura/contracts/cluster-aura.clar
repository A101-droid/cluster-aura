;; ClusterAura - Decentralized Professional Identity Ecosystem
;; 
;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-ALREADY-EXISTS        (err u101))
(define-constant ERR-NOT-FOUND             (err u102))
(define-constant ERR-INVALID-TIER          (err u103))
(define-constant ERR-INVALID-PROOF         (err u104))
(define-constant ERR-ALREADY-VALIDATED     (err u105))
(define-constant ERR-SELF-VALIDATION       (err u106))
(define-constant ERR-PROJECT-NOT-OPEN      (err u107))
(define-constant ERR-ALREADY-MEMBER        (err u108))
(define-constant ERR-INSUFFICIENT-MEMBERS  (err u109))

;; Tier identifiers
(define-constant TIER-INSTITUTIONAL u1)
(define-constant TIER-PEER          u2)
(define-constant TIER-PROJECT       u3)

;; Minimum members required to complete a project credential
(define-constant MIN-PROJECT-MEMBERS u2)

;; Aura score weights (out of 100 total)
(define-constant WEIGHT-PEER-VALIDATIONS  u50)
(define-constant WEIGHT-PROJECT-COMPLETIONS u30)
(define-constant WEIGHT-SKILL-COUNT       u20)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Tracks registered professionals
(define-map professionals
  { owner: principal }
  {
    registered-at: uint,
    aura-score:    uint,
    active:        bool
  }
)

;; NFT token id counter
(define-data-var next-token-id uint u1)

;; Privacy Credential NFT - non-fungible token
;; The token-id maps to a credential record below
(define-non-fungible-token privacy-credential uint)

;; Credential records keyed by token-id
(define-map credentials
  { token-id: uint }
  {
    owner:            principal,
    tier:             uint,
    ;; encrypted-metadata is a hash or ciphertext commitment stored as a buff
    encrypted-metadata: (buff 64),
    ;; merkle-root represents the root of the privacy-preserving merkle tree
    merkle-root:      (buff 32),
    attester:         (optional principal),
    created-at:       uint,
    active:           bool
  }
)

;; Peer validations: tracks who validated which credential
(define-map peer-validations
  { token-id: uint, validator: principal }
  { validated-at: uint }
)

;; Peer validation counts per credential
(define-map validation-counts
  { token-id: uint }
  { count: uint }
)

;; Project credentials: multi-party completions
(define-map project-credentials
  { token-id: uint }
  {
    status:      (string-ascii 16),   ;; "open" | "completed"
    member-count: uint
  }
)

;; Project membership: tracks which principals are part of a project credential
(define-map project-members
  { token-id: uint, member: principal }
  { joined-at: uint }
)

;; Employer/client competency proof requests
(define-map proof-requests
  { request-id: uint }
  {
    requester:   principal,
    token-id:    uint,
    ;; merkle-proof is supplied by the credential owner off-chain; stored on-chain for auditability
    merkle-proof: (buff 64),
    verified:    bool,
    created-at:  uint
  }
)

(define-data-var next-request-id uint u1)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Returns the current aura score for a professional, defaulting to 0
(define-private (get-aura-score (owner principal))
  (match (map-get? professionals { owner: owner })
    prof (get aura-score prof)
    u0
  )
)

;; Recalculates and persists aura score for a professional
;; Score = (peer-validations * WEIGHT-PEER) + (project-completions * WEIGHT-PROJECT) + (skill-count * WEIGHT-SKILL)
;; Values are capped at u100 per component to prevent runaway scores.
(define-private (refresh-aura-score (owner principal))
  (let (
    (peer-val   (get-peer-validation-total owner))
    (proj-comp  (get-project-completion-total owner))
    (skill-cnt  (get-skill-count owner))
    (raw-score  (+
                  (* (if (> peer-val  u100) u100 peer-val)  WEIGHT-PEER-VALIDATIONS)
                  (* (if (> proj-comp u100) u100 proj-comp) WEIGHT-PROJECT-COMPLETIONS)
                  (* (if (> skill-cnt u100) u100 skill-cnt) WEIGHT-SKILL-COUNT)
                ))
    (final-score (/ raw-score u100))
  )
    (match (map-get? professionals { owner: owner })
      prof (map-set professionals { owner: owner }
              (merge prof { aura-score: final-score }))
      false
    )
  )
)

;; Count active peer validations across all credentials owned by a principal
;; NOTE: Clarity lacks iteration, so we use a data-var accumulator pattern.
;;       Callers update this count via the validation-counts map.
(define-private (get-peer-validation-total (owner principal))
  ;; Approximation: sum validation counts for up to the current token window.
  ;; In production, maintain a per-owner aggregate map for gas efficiency.
  (default-to u0 (get total (map-get? owner-peer-totals { owner: owner })))
)

(define-map owner-peer-totals { owner: principal } { total: uint })
(define-private (increment-owner-peer-total (owner principal))
  (let ((current (default-to u0 (get total (map-get? owner-peer-totals { owner: owner })))))
    (map-set owner-peer-totals { owner: owner } { total: (+ current u1) })
  )
)

;; Track project completion count per owner
(define-map owner-project-totals { owner: principal } { total: uint })
(define-private (get-project-completion-total (owner principal))
  (default-to u0 (get total (map-get? owner-project-totals { owner: owner })))
)
(define-private (increment-owner-project-total (owner principal))
  (let ((current (default-to u0 (get total (map-get? owner-project-totals { owner: owner })))))
    (map-set owner-project-totals { owner: owner } { total: (+ current u1) })
  )
)

;; Track skill/credential count per owner
(define-map owner-skill-counts { owner: principal } { total: uint })
(define-private (get-skill-count (owner principal))
  (default-to u0 (get total (map-get? owner-skill-counts { owner: owner })))
)
(define-private (increment-skill-count (owner principal))
  (let ((current (default-to u0 (get total (map-get? owner-skill-counts { owner: owner })))))
    (map-set owner-skill-counts { owner: owner } { total: (+ current u1) })
  )
)

;; ============================================================
;; PROFESSIONAL REGISTRATION
;; ============================================================

;; Register a new professional identity on the platform
(define-public (register-professional)
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? professionals { owner: caller })) ERR-ALREADY-EXISTS)
    (map-set professionals { owner: caller }
      {
        registered-at: block-height,
        aura-score:    u0,
        active:        true
      }
    )
    (ok true)
  )
)

;; ============================================================
;; CREDENTIAL MINTING
;; ============================================================

;; Mint a new Privacy Credential NFT.
;; tier must be TIER-INSTITUTIONAL (1), TIER-PEER (2), or TIER-PROJECT (3).
;; encrypted-metadata: caller-provided encrypted skill data commitment (buff 64).
;; merkle-root: root of the off-chain merkle tree for this credential cluster (buff 32).
;; attester: optional institutional attester principal (required for Tier 1).
(define-public (mint-credential
    (tier              uint)
    (encrypted-metadata (buff 64))
    (merkle-root        (buff 32))
    (attester           (optional principal))
  )
  (let (
    (caller   tx-sender)
    (token-id (var-get next-token-id))
  )
    ;; Caller must be a registered professional
    (asserts! (is-some (map-get? professionals { owner: caller })) ERR-NOT-AUTHORIZED)
    ;; Validate tier
    (asserts! (or (is-eq tier TIER-INSTITUTIONAL)
                  (or (is-eq tier TIER-PEER) (is-eq tier TIER-PROJECT)))
              ERR-INVALID-TIER)
    ;; Institutional credentials require an attester
    (asserts! (or (not (is-eq tier TIER-INSTITUTIONAL)) (is-some attester)) ERR-NOT-AUTHORIZED)

    ;; Mint the NFT to the caller
    (try! (nft-mint? privacy-credential token-id caller))

    ;; Store credential record
    (map-set credentials { token-id: token-id }
      {
        owner:             caller,
        tier:              tier,
        encrypted-metadata: encrypted-metadata,
        merkle-root:       merkle-root,
        attester:          attester,
        created-at:        block-height,
        active:            true
      }
    )

    ;; Initialize validation count
    (map-set validation-counts { token-id: token-id } { count: u0 })

    ;; If project tier, initialize project record
    (if (is-eq tier TIER-PROJECT)
      (map-set project-credentials { token-id: token-id }
        { status: "open", member-count: u0 }
      )
      false
    )

    ;; Update owner counters and advance token id
    (increment-skill-count caller)
    (var-set next-token-id (+ token-id u1))
    (refresh-aura-score caller)

    (ok token-id)
  )
)

;; ============================================================
;; TIER 2 - PEER VALIDATION
;; ============================================================

;; Validate another professional's credential (Tier 2).
;; Any registered professional may validate; they cannot validate their own credentials.
(define-public (validate-credential (token-id uint))
  (let (
    (validator tx-sender)
    (cred      (unwrap! (map-get? credentials { token-id: token-id }) ERR-NOT-FOUND))
    (owner     (get owner cred))
  )
    ;; Caller must be registered
    (asserts! (is-some (map-get? professionals { owner: validator })) ERR-NOT-AUTHORIZED)
    ;; No self-validation
    (asserts! (not (is-eq validator owner)) ERR-SELF-VALIDATION)
    ;; Credential must be active and peer-tier (or any tier is validatable)
    (asserts! (get active cred) ERR-NOT-FOUND)
    ;; No duplicate validations
    (asserts! (is-none (map-get? peer-validations { token-id: token-id, validator: validator }))
              ERR-ALREADY-VALIDATED)

    ;; Record validation
    (map-set peer-validations { token-id: token-id, validator: validator }
      { validated-at: block-height }
    )

    ;; Increment counts
    (let ((current-count (default-to u0
            (get count (map-get? validation-counts { token-id: token-id })))))
      (map-set validation-counts { token-id: token-id }
        { count: (+ current-count u1) }
      )
    )
    (increment-owner-peer-total owner)
    (refresh-aura-score owner)

    (ok true)
  )
)

;; ============================================================
;; TIER 3 - MULTI-PARTY PROJECT COMPLETIONS
;; ============================================================

;; Join an open project credential as a collaborating member.
(define-public (join-project (token-id uint))
  (let (
    (caller  tx-sender)
    (cred    (unwrap! (map-get? credentials { token-id: token-id }) ERR-NOT-FOUND))
    (project (unwrap! (map-get? project-credentials { token-id: token-id }) ERR-NOT-FOUND))
  )
    (asserts! (is-some (map-get? professionals { owner: caller })) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status project) "open") ERR-PROJECT-NOT-OPEN)
    (asserts! (is-none (map-get? project-members { token-id: token-id, member: caller }))
              ERR-ALREADY-MEMBER)

    (map-set project-members { token-id: token-id, member: caller }
      { joined-at: block-height }
    )
    (map-set project-credentials { token-id: token-id }
      { status: "open", member-count: (+ (get member-count project) u1) }
    )

    (ok true)
  )
)

;; Complete a project credential once the minimum member threshold is met.
;; Only the credential owner may trigger completion.
(define-public (complete-project (token-id uint))
  (let (
    (caller  tx-sender)
    (cred    (unwrap! (map-get? credentials { token-id: token-id }) ERR-NOT-FOUND))
    (project (unwrap! (map-get? project-credentials { token-id: token-id }) ERR-NOT-FOUND))
  )
    (asserts! (is-eq caller (get owner cred)) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status project) "open") ERR-PROJECT-NOT-OPEN)
    (asserts! (>= (get member-count project) MIN-PROJECT-MEMBERS) ERR-INSUFFICIENT-MEMBERS)

    (map-set project-credentials { token-id: token-id }
      (merge project { status: "completed" })
    )

    (increment-owner-project-total caller)
    (refresh-aura-score caller)

    (ok true)
  )
)

;; ============================================================
;; COMPETENCY PROOF REQUESTS (Employer / Client Flow)
;; ============================================================

;; Submit a competency proof request for a specific credential.
;; merkle-proof is the selective-disclosure proof supplied by the credential owner
;; (generated off-chain). The contract records and marks it verified if the credential
;; is active and the proof is non-empty.
(define-public (request-competency-proof
    (token-id    uint)
    (merkle-proof (buff 64))
  )
  (let (
    (requester  tx-sender)
    (request-id (var-get next-request-id))
    (cred       (unwrap! (map-get? credentials { token-id: token-id }) ERR-NOT-FOUND))
  )
    (asserts! (get active cred) ERR-NOT-FOUND)
    ;; Proof must be non-empty (basic on-chain sanity check)
    (asserts! (> (len merkle-proof) u0) ERR-INVALID-PROOF)

    (map-set proof-requests { request-id: request-id }
      {
        requester:    requester,
        token-id:     token-id,
        merkle-proof: merkle-proof,
        ;; Mark as verified: full ZK verification would occur off-chain;
        ;; on-chain we confirm the proof was provided for the active credential.
        verified:     true,
        created-at:   block-height
      }
    )

    (var-set next-request-id (+ request-id u1))

    (ok request-id)
  )
)

;; ============================================================
;; ADMIN - REVOKE CREDENTIAL
;; ============================================================

;; Revoke (deactivate) a credential. Only the credential owner or the contract
;; owner may revoke. Does not burn the NFT; marks record inactive.
(define-public (revoke-credential (token-id uint))
  (let (
    (caller tx-sender)
    (cred   (unwrap! (map-get? credentials { token-id: token-id }) ERR-NOT-FOUND))
  )
    (asserts! (or (is-eq caller (get owner cred))
                  (is-eq caller CONTRACT-OWNER))
              ERR-NOT-AUTHORIZED)
    (asserts! (get active cred) ERR-NOT-FOUND)

    (map-set credentials { token-id: token-id }
      (merge cred { active: false })
    )

    (ok true)
  )
)

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

;; Get professional profile including aura score
(define-read-only (get-professional (owner principal))
  (map-get? professionals { owner: owner })
)

;; Get credential record (metadata is encrypted; callers cannot read plaintext skills)
(define-read-only (get-credential (token-id uint))
  (map-get? credentials { token-id: token-id })
)

;; Get peer validation count for a credential
(define-read-only (get-validation-count (token-id uint))
  (default-to u0 (get count (map-get? validation-counts { token-id: token-id })))
)

;; Check if a specific principal has validated a credential
(define-read-only (has-validated (token-id uint) (validator principal))
  (is-some (map-get? peer-validations { token-id: token-id, validator: validator }))
)

;; Get project credential status
(define-read-only (get-project-status (token-id uint))
  (map-get? project-credentials { token-id: token-id })
)

;; Get aura score for a professional
(define-read-only (get-aura (owner principal))
  (get-aura-score owner)
)

;; Get proof request by id
(define-read-only (get-proof-request (request-id uint))
  (map-get? proof-requests { request-id: request-id })
)

;; Get the NFT owner for a token
(define-read-only (get-token-owner (token-id uint))
  (nft-get-owner? privacy-credential token-id)
)
