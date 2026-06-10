import type {
	AuditInput,
	AuthenticateInput,
	AuthenticateResult,
	IamRpc,
	IssueCapabilityInput,
	IssueCapabilityResult,
	RedeemCapabilityInput,
	RedeemCapabilityResult,
} from '@propustka/core'

/**
 * In-memory `IamRpc` stub for SDK tests — no network. Returns canned authenticate/redeem/
 * issue results and records every `audit` call so tests can assert the auto-attached fields.
 */
export class IamRpcStub implements IamRpc {
	readonly auditCalls: AuditInput[] = []
	readonly authenticateInputs: AuthenticateInput[] = []
	readonly redeemInputs: RedeemCapabilityInput[] = []
	readonly issueInputs: IssueCapabilityInput[] = []

	constructor(
		private readonly canned: {
			authenticate?: AuthenticateResult
			redeem?: RedeemCapabilityResult
			issue?: IssueCapabilityResult
		} = {},
	) {}

	authenticate(input: AuthenticateInput): Promise<AuthenticateResult> {
		this.authenticateInputs.push(input)
		return Promise.resolve(
			this.canned.authenticate ?? { ok: false, reason: 'missing_token' },
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
