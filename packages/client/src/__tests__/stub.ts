import type {
	AuditInput,
	AuthenticateInput,
	AuthenticateResult,
	IamRpc,
	IssueCapabilityInput,
	IssueCapabilityResult,
	IssueServiceTokenInput,
	IssueServiceTokenResult,
	Jwks,
	ListPrincipalsInput,
	ListPrincipalsResult,
	MintTokenInput,
	MintTokenResult,
	RedeemCapabilityInput,
	RedeemCapabilityResult,
	RevokeCapabilityInput,
	RevokeCapabilityResult,
	RevokeServiceTokenInput,
	RevokeServiceTokenResult,
	RotateServiceTokenInput,
	RotateServiceTokenResult,
} from '@propustka/core'

/**
 * In-memory `IamRpc` stub for SDK tests — no network. Returns canned authenticate/redeem/
 * issue/revoke results and records every `audit` call so tests can assert the auto-attached fields.
 */
export class IamRpcStub implements IamRpc {
	readonly auditCalls: AuditInput[] = []
	readonly authenticateInputs: AuthenticateInput[] = []
	readonly redeemInputs: RedeemCapabilityInput[] = []
	readonly issueInputs: IssueCapabilityInput[] = []
	readonly revokeInputs: RevokeCapabilityInput[] = []
	readonly issueServiceInputs: IssueServiceTokenInput[] = []
	readonly revokeServiceInputs: RevokeServiceTokenInput[] = []
	readonly rotateServiceInputs: RotateServiceTokenInput[] = []
	readonly listPrincipalsInputs: ListPrincipalsInput[] = []
	readonly mintTokenInputs: MintTokenInput[] = []

	constructor(
		private readonly canned: {
			authenticate?: AuthenticateResult
			redeem?: RedeemCapabilityResult
			issue?: IssueCapabilityResult
			revoke?: RevokeCapabilityResult
			issueService?: IssueServiceTokenResult
			revokeService?: RevokeServiceTokenResult
			rotateService?: RotateServiceTokenResult
			listPrincipals?: ListPrincipalsResult
			mintToken?: MintTokenResult
			jwks?: Jwks
		} = {},
	) {}

	mintToken(input: MintTokenInput): Promise<MintTokenResult> {
		this.mintTokenInputs.push(input)
		return Promise.resolve(this.canned.mintToken ?? { ok: false, reason: 'no_session' })
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

	redeemCapability(input: RedeemCapabilityInput): Promise<RedeemCapabilityResult> {
		this.redeemInputs.push(input)
		return Promise.resolve(
			this.canned.redeem ?? { ok: false, reason: 'unknown' },
		)
	}

	issueCapability(input: IssueCapabilityInput): Promise<IssueCapabilityResult> {
		this.issueInputs.push(input)
		return Promise.resolve(
			this.canned.issue ?? { ok: false, reason: 'not_allowed' },
		)
	}

	revokeCapability(input: RevokeCapabilityInput): Promise<RevokeCapabilityResult> {
		this.revokeInputs.push(input)
		return Promise.resolve(
			this.canned.revoke ?? { ok: false, reason: 'not_found' },
		)
	}

	issueServiceToken(input: IssueServiceTokenInput): Promise<IssueServiceTokenResult> {
		this.issueServiceInputs.push(input)
		return Promise.resolve(
			this.canned.issueService ?? { ok: false, reason: 'not_allowed' },
		)
	}

	revokeServiceToken(input: RevokeServiceTokenInput): Promise<RevokeServiceTokenResult> {
		this.revokeServiceInputs.push(input)
		return Promise.resolve(
			this.canned.revokeService ?? { ok: false, reason: 'not_found' },
		)
	}

	rotateServiceToken(input: RotateServiceTokenInput): Promise<RotateServiceTokenResult> {
		this.rotateServiceInputs.push(input)
		return Promise.resolve(
			this.canned.rotateService ?? { ok: false, reason: 'not_found' },
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
