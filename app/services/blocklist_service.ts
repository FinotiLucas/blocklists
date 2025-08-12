import { writeFile } from 'node:fs/promises'
import type { BlocklistConfig, DomainSet } from '#types/blocklist'
import HttpClient from '#utils/http_client'

/**
 * Serviço para consolidação de blocklists do Pi-hole.
 */
export default class BlocklistService {
  /**
   * Configuração das blocklists, com segmentos já formatados.
   * @private
   */
  private readonly blocklists: BlocklistConfig = {
    suspicious: [
      'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt',
      'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts',
      'https://v.firebog.net/hosts/static/w3kbl.txt',
      'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt',
      'https://someonewhocares.org/hosts/zero/hosts',
      'https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts',
      'https://winhelp2002.mvps.org/hosts.txt',
      'https://v.firebog.net/hosts/neohostsbasic.txt',
      'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt',
      'https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt',
    ],
    advertising: [
      'https://adaway.org/hosts.txt',
      'https://v.firebog.net/hosts/AdguardDNS.txt',
      'https://v.firebog.net/hosts/Admiral.txt',
      'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
      'https://v.firebog.net/hosts/Easylist.txt',
      'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
      'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts',
      'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts',
    ],
    tracking_telemetry: [
      'https://v.firebog.net/hosts/Easyprivacy.txt',
      'https://v.firebog.net/hosts/Prigent-Ads.txt',
      'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts',
      'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
      'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt',
      'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt',
      'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt',
      'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt',
      'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',
    ],
  }

  private readonly httpClient: HttpClient

  /**
   * Construtor do BlocklistService.
   * @param httpClient - Instância do cliente HTTP (opcional, cria um novo se não fornecido).
   */
  constructor(httpClient: HttpClient = new HttpClient()) {
    this.httpClient = httpClient
  }

  /**
   * Extrai domínios válidos de um conteúdo de blocklist.
   * @param content - Conteúdo bruto da blocklist.
   * @returns Conjunto de domínios únicos.
   */
  private extractDomains(content: string): Set<string> {
    const domainPattern = /^(?:0\.0\.0\.0\s+|127\.0\.0\.1\s+)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$/gm
    const domains = new Set<string>()
    let match: RegExpExecArray | null

    while ((match = domainPattern.exec(content)) !== null) {
      domains.add(match[1])
    }

    return domains
  }

  /**
   * Baixa uma blocklist de uma URL.
   * @param url - URL da blocklist.
   * @returns Conjunto de domínios extraídos ou vazio em caso de erro.
   */
  private async fetchList(url: string): Promise<DomainSet> {
    const content = await this.httpClient.get(url)
    return { domains: this.extractDomains(content) }
  }

  /**
   * Consolida listas de um segmento em um arquivo.
   * @param urls - Lista de URLs do segmento.
   * @param outputFile - Caminho do arquivo de saída.
   */
  private async consolidateSegment(urls: string[], outputFile: string): Promise<void> {
    const domainSets = await Promise.all(urls.map((url) => this.fetchList(url)))
    const allDomains = new Set<string>()

    domainSets.forEach(({ domains }) => domains.forEach((domain) => allDomains.add(domain)))

    const formattedContent = [...allDomains]
      .sort()
      .map((domain) => `0.0.0.0 ${domain}`)
      .join('\n')

    await writeFile(outputFile, formattedContent)
    console.log(`Arquivo salvo: ${outputFile} com ${allDomains.size} domínios.`)
  }

  /**
   * Processa todas as blocklists e gera arquivos consolidados por segmento.
   */
  public async consolidateAll(): Promise<void> {
    const tasks = Object.entries(this.blocklists).map(([segment, urls]) =>
      this.consolidateSegment(urls, `${segment}.txt`)
    )

    await Promise.all(tasks)
    console.log('Consolidação concluída.')
  }
}
