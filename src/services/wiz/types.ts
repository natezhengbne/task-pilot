export interface WizVulnerableAsset {
  id?: string | null;
  type?: string | null;
  name?: string | null;
  cloudPlatform?: string | null;
  nativeType?: string | null;
  externalId?: string | null;
  repositoryId?: string | null;
  repositoryName?: string | null;
}

export interface WizRawVulnerabilityNode {
  id?: string | null;
  name?: string | null;
  detailedName?: string | null;
  description?: string | null;
  severity?: string | null;
  status?: string | null;
  version?: string | null;
  fixedVersion?: string | null;
  recommendedVersion?: string | null;
  locationPath?: string | null;
  detectionMethod?: string | null;
  codeLibraryLanguage?: string | null;
  transitivity?: string | null;
  rootComponent?: { name?: string | null } | null;
  vulnerableAsset?: WizVulnerableAsset | null;
  score?: number | null;
  hasExploit?: boolean | null;
  hasCisaKevExploit?: boolean | null;
  firstDetectedAt?: string | null;
  lastDetectedAt?: string | null;
}

export interface WizGraphQLResponse {
  data?: {
    vulnerabilityFindings?: {
      nodes?: WizRawVulnerabilityNode[] | null;
    } | null;
  } | null;
}
