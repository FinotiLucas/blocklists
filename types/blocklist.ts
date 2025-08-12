/**
 * Interface para configuração de blocklists por segmento.
 */
export interface BlocklistConfig {
  [segment: string]: string[]
}

/**
 * Interface para conjunto de domínios extraídos.
 */
export interface DomainSet {
  domains: Set<string>
}
