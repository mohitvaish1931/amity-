// Shared typed contracts for Sentinel X.
// Parser, security model and (future) runtime layers all exchange these shapes.
// Nothing here has behaviour; see src/openapi and src/model for producers.

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE";
export type SpecFormat = "openapi-3.0" | "openapi-3.1" | "swagger-2.0";
export type Sensitivity = "PUBLIC" | "PERSONAL" | "INTERNAL" | "SENSITIVE";
export type ParameterLocation = "path" | "query" | "header" | "cookie";
export type JsonPrimitive = string | number | boolean | null;

// ---------- schemas ----------

/** One leaf or container in a flattened schema. `path` uses dots for objects and `[]` for arrays. */
export interface Field {
  path: string;
  name: string;
  type: string;
  format?: string;
  nullable: boolean;
  required: boolean;
  enum?: readonly JsonPrimitive[];
  /** Name of the component schema this field points at, if it was a $ref. */
  ref?: string;
  /** True when flattening stopped because the $ref chain loops back on itself. */
  recursive?: boolean;
  /** Set for fields that only exist in one branch of oneOf/anyOf, e.g. "oneOf:Cat". */
  variant?: string;
}

export interface SchemaInfo {
  /** Component name when the schema is (or wraps) a $ref. */
  refName?: string;
  type: string;
  isArray: boolean;
  /** Component name of array items, when items are a $ref. */
  itemRefName?: string;
  nullable: boolean;
  enum?: readonly JsonPrimitive[];
  fields: Field[];
}

// ---------- operations ----------

export interface Parameter {
  name: string;
  in: ParameterLocation;
  required: boolean;
  description?: string;
  schema: SchemaInfo;
}

export interface MediaContent {
  contentType: string;
  schema: SchemaInfo | null;
}

export interface RequestBody {
  required: boolean;
  contents: MediaContent[];
}

export interface ResponseSpec {
  status: string;
  description?: string;
  contents: MediaContent[];
}

export interface SecuritySchemeRef {
  name: string;
  /** apiKey | http | oauth2 | openIdConnect | basic (Swagger 2) | unknown */
  type: string;
  scheme?: string;
  in?: string;
  paramName?: string;
  scopes: string[];
  /** False when a requirement names a scheme that is not declared in the spec. */
  known: boolean;
}

/** All schemes inside one alternative are required together (AND). Alternatives are OR-ed. */
export interface SecurityAlternative {
  schemes: SecuritySchemeRef[];
}

/**
 * required: every alternative needs credentials.
 * optional: an empty alternative ({}) allows anonymous access next to authenticated access.
 * public:   security: [] or no requirement declared anywhere.
 */
export type AuthMode = "required" | "optional" | "public";

export interface AuthRequirement {
  mode: AuthMode;
  /** Where the effective requirement came from. "none" = nothing declared at operation or root level. */
  source: "operation" | "root" | "none";
  alternatives: SecurityAlternative[];
  detail: string;
}

export type Action = "Read" | "List" | "Create" | "Update" | "Delete" | "AdminAction" | "Other";

export interface ResourceEvidence {
  source: "schema" | "path" | "operationId" | "tag";
  value: string;
  weight: number;
}

export interface Endpoint {
  id: string;
  method: HttpMethod;
  path: string;
  operationId?: string;
  summary?: string;
  tags: string[];
  deprecated: boolean;
  parameters: Parameter[];
  requestBody: RequestBody | null;
  responses: ResponseSpec[];
  auth: AuthRequirement;
  action: Action;
  resource: string;
  resourceEvidence: ResourceEvidence[];
  /** 0..1, share of evidence weight that agrees with the chosen resource. */
  resourceConfidence: number;
}

// ---------- security model ----------

export interface ResourceField extends Field {
  sensitivity: Sensitivity;
  sensitivityReason: string;
}

export type RelationshipKind = "references" | "returned-by" | "accepted-by";

export interface Relationship {
  from: string;
  to: string;
  kind: RelationshipKind;
  /** Field path or endpoint id that establishes the relationship. */
  via: string;
}

export interface Resource {
  name: string;
  endpoints: string[];
  schemaNames: string[];
  fields: ResourceField[];
  ownershipField: string | null;
  identifierFields: string[];
  relations: Relationship[];
}

export interface Identity {
  id: string;
  name: string;
  role: string;
}

export interface Role {
  name: string;
  permissions: Record<string, boolean>;
  privileged: boolean;
  /** Where `privileged` came from (e.g. explicit configuration or a name heuristic). Shown as provenance. */
  privilegeEvidence?: string;
}

export interface ApiModel {
  format: SpecFormat;
  specVersion: string;
  title?: string;
  apiVersion?: string;
  servers: string[];
  securitySchemes: Record<string, SecuritySchemeRef>;
  endpoints: Endpoint[];
  schemas: Record<string, SchemaInfo>;
  resources: Resource[];
  warnings: string[];
}

// ---------- constitution, tests, findings ----------

export type Severity = "Low" | "Medium" | "High" | "Critical";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

/** Security Constitution law categories. */
export type LawCategory =
  | "AUTHENTICATION"
  | "OBJECT_AUTHORIZATION"
  | "FUNCTION_AUTHORIZATION"
  | "DATA_EXPOSURE"
  | "STATE_TRANSITION"
  | "SECURITY_CONFIGURATION";

/** Categories of the Step 1 → Step 2 export contract (testable-security-model.json `laws`). */
export type LegacyLawCategory = "BOLA" | "ADMIN" | "DATA" | "AUTHN" | "ROLE" | "POLICY";

/** Model entities a law governs. Field entries are "Resource.fieldPath"; identities are configured identity ids. */
export interface LawScope {
  endpoints: string[];
  resources: string[];
  fields: string[];
  roles: string[];
  identities: string[];
}

export type ProvenanceKind =
  | "endpoint"
  | "path"
  | "security"
  | "schema"
  | "sensitivity"
  | "relationship"
  | "role"
  | "identity"
  | "ownership"
  | "permission";

/** One piece of model/configuration evidence behind a law, e.g. { ref: "schema:Order.customerId" }. */
export interface Provenance {
  kind: ProvenanceKind;
  ref: string;
  detail: string;
}

export interface ConfidenceSignal {
  id: string;
  description: string;
  present: boolean;
}

/** Why a law has its confidence: which evidence signals were present and which were missing. */
export interface ConfidenceRationale {
  level: Confidence;
  /** Share of signals present, 0..100. */
  score: number;
  signals: ConfidenceSignal[];
  rule: string;
}

/** Machine-readable form of a law, kept separate from the human-readable statement. */
export type LawRule =
  | { type: "requires-authentication"; endpoints: string[]; schemes: string[] }
  | { type: "owner-only-access"; resource: string; ownershipField: string | null; subjectRoles: string[]; endpoints: string[]; operations: ("read" | "write")[] }
  | { type: "role-restricted"; endpoints: string[]; allowedRoles: string[]; deniedRoles: string[] }
  | {
      type: "no-unauthorized-field-exposure";
      resource: string;
      fields: string[];
      endpoints: string[];
      ownershipField: string | null;
      /** "Parent.field" when entitlement follows an owned parent the resource is only reachable through. */
      inheritedFrom: string | null;
    }
  | { type: "guarded-state-transition"; resource: string; stateField: string; states: string[]; endpoints: string[] }
  | { type: "explicit-public-access"; endpoints: string[]; mode: "public" | "optional"; exposesSensitiveFields: string[] }
  | { type: "declared-security-schemes"; endpoints: string[]; undeclaredSchemes: string[] }
  | { type: "permission-matrix"; roles: string[]; contestedActions: string[] };

/** Static test specification. Sentinel X does not execute these in the current phase. */
export interface TestStrategy {
  kind: string;
  preconditions: string[];
  steps: string[];
  expected: string;
  executable: false;
}

export interface SecurityLaw {
  id: string;
  /** Deduplication key: laws with the same key are merged. */
  key: string;
  category: LawCategory;
  severity: Severity;
  statement: string;
  rule: LawRule;
  /** Formal rendering of `rule`, for display. */
  invariant: string;
  appliesTo: LawScope;
  provenance: Provenance[];
  confidence: Confidence;
  confidenceRationale: ConfidenceRationale;
  testStrategy: TestStrategy;
}

export interface SecurityConstitution {
  version: "constitution-v1";
  laws: SecurityLaw[];
  /** Model facts that prevented a law from being generated or limited its confidence. */
  notes: string[];
}

export type ExpectedOutcome = "ALLOW" | "DENY";

export interface TestCase {
  id: string;
  lawId: string;
  category: LawCategory;
  endpointId: string;
  method: HttpMethod;
  path: string;
  identityId: string | null;
  objectId?: string;
  expected: ExpectedOutcome;
}

export type TestStatus = "PASS" | "VIOLATION" | "INCONCLUSIVE" | "ERROR" | "SKIPPED";

export interface TestResult {
  testId: string;
  status: TestStatus;
  observedStatus?: number;
  executedAt?: string;
  /** True for simulated (mock) execution. Simulated results can never back a CONFIRMED finding. */
  simulated: boolean;
  reason: string;
}

export type FindingState = "SUSPECTED" | "OBSERVED" | "CONFIRMED";

export interface Evidence {
  testId: string;
  identityId: string | null;
  endpoint: string;
  objectId?: string;
  expected: ExpectedOutcome;
  observedStatus: number;
  /** Header values must already be redacted before they reach this type. */
  request: { method: HttpMethod; url: string; headers: Record<string, string> };
  response: { status: number; headers: Record<string, string>; bodyExcerpt: string };
  startedAt: string;
  finishedAt: string;
  reproductionCount: number;
  simulated: boolean;
}

export interface Finding {
  id: string;
  state: FindingState;
  lawId: string;
  category: LawCategory;
  endpointId: string;
  summary: string;
  evidence: Evidence[];
}
