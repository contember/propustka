import type {
	AuditInput,
	AuthenticateInput,
	AuthenticateResult,
	IamRpc,
	IssueJwtInput,
	IssueJwtResult,
	IssueKeyInput,
	IssueKeyResult,
	Jwks,
	ListPrincipalsInput,
	ListPrincipalsResult,
	MintFromKeyInput,
	MintFromKeyResult,
	MintTokenInput,
	MintTokenResult,
	RevokeKeyInput,
	RevokeKeyResult,
} from '@propustka/core'

/**
 * In-memory `IamRpc` stub for SDK tests — no network. Returns canned authenticate/mint/issue/
 * revoke results and records every `audit` call so tests can assert the auto-attached fields.
 */
export class IamRpcStub implements IamRpc {
	readonly auditCalls: AuditInput[] = []
	readonly authenticateInputs: AuthenticateInput[] = []
	readonly revokeKeyInputs: RevokeKeyInput[] = []
	readonly listPrincipalsInputs: ListPrincipalsInput[] = []
	readonly mintTokenInputs: MintTokenInput[] = []
	readonly mintFromKeyInputs: MintFromKeyInput[] = []
	readonly issueKeyInputs: IssueKeyInput[] = []
	readonly issueJwtInputs: IssueJwtInput[] = []

	constructor(
		private readonly canned: {
			authenticate?: AuthenticateResult
			revokeKey?: RevokeKeyResult
			listPrincipals?: ListPrincipalsResult
			mintToken?: MintTokenResult
			mintFromKey?: MintFromKeyResult
			issueKey?: IssueKeyResult
			issueJwt?: IssueJwtResult
			jwks?: Jwks
		} = {},
	) {}

	mintToken(input: MintTokenInput): Promise<MintTokenResult> {
		this.mintTokenInputs.push(input)
		return Promise.resolve(this.canned.mintToken ?? { ok: false, reason: 'no_session' })
	}

	mintFromKey(input: MintFromKeyInput): Promise<MintFromKeyResult> {
		this.mintFromKeyInputs.push(input)
		return Promise.resolve(this.canned.mintFromKey ?? { ok: false, reason: 'invalid_key' })
	}

	issueKey(input: IssueKeyInput): Promise<IssueKeyResult> {
		this.issueKeyInputs.push(input)
		return Promise.resolve(this.canned.issueKey ?? { ok: false, reason: 'not_allowed' })
	}

	issueJwt(input: IssueJwtInput): Promise<IssueJwtResult> {
		this.issueJwtInputs.push(input)
		return Promise.resolve(this.canned.issueJwt ?? { ok: false, reason: 'not_allowed' })
	}

	getJwks(): Promise<Jwks> {
		return Promise.resolve(this.canned.jwks ?? { keys: [] })
	}

	authenticate(input: AuthenticateInput): Promise<AuthenticateResult> {
		this.authenticateInputs.push(input)
		return Promise.resolve(
			this.canned.authenticate ?? { ok: false, reason: 'missing_token' },
		)
	}

	listPrincipals(input: ListPrincipalsInput): Promise<ListPrincipalsResult> {
		this.listPrincipalsInputs.push(input)
		return Promise.resolve(
			this.canned.listPrincipals ?? { ok: false, reason: 'not_allowed' },
		)
	}

	audit(event: AuditInput): Promise<void> {
		this.auditCalls.push(event)
		return Promise.resolve()
	}

	revokeKey(input: RevokeKeyInput): Promise<RevokeKeyResult> {
		this.revokeKeyInputs.push(input)
		return Promise.resolve(
			this.canned.revokeKey ?? { ok: false, reason: 'not_found' },
		)
	}
}

/** Build a Request carrying forwarded Access credentials + a cf-ray. */
export function makeRequest(opts: {
	url?: string
	token?: string
	cookie?: string
	ray?: string
} = {}): Request {
	const headers = new Headers()
	if (opts.token !== undefined) {
		headers.set('Cf-Access-Jwt-Assertion', opts.token)
	}
	if (opts.cookie !== undefined) {
		headers.set('Cookie', `CF_Authorization=${opts.cookie}; other=ignored`)
	}
	if (opts.ray !== undefined) {
		headers.set('cf-ray', opts.ray)
	}
	return new Request(opts.url ?? 'https://app.example.com/path', { headers })
}
