import type { BlocklistConfig } from '#types/blocklist'
import HttpClient from '#utils/http_client'
import BlockList from '#models/block_list'
import db from '@adonisjs/lucid/services/db'
import { createInterface } from 'node:readline'
import { Readable } from 'node:stream'

/**
 * Serviço para consolidação de blocklists do Pi-hole.
 */
export default class BlocklistService {
  /**
   * Configuração das blocklists, com segmentos já formatados.
   * @private
   */
  private readonly blockLists: BlocklistConfig = {
    suspicious: [
      //'https://big.oisd.nl',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Miningpages.txt',
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
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Adsandtrackers.txt',
      'https://adaway.org/hosts.txt',
      'https://v.firebog.net/hosts/AdguardDNS.txt',
      'https://v.firebog.net/hosts/Admiral.txt',
      'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
      'https://v.firebog.net/hosts/Easylist.txt',
      'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
      'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts',
      'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts',
    ],
    telemetry: [
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Telemetry.txt',
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
    malicious: [
      'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/spam.mails.txt',
      'https://v.firebog.net/hosts/Prigent-Crypto.txt',
      'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts',
      'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt',
      'https://phishing.army/download/phishing_army_blocklist_extended.txt',
      'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt',
      'https://v.firebog.net/hosts/RPiList-Malware.txt',
      'https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt',
      'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts',
      'https://urlhaus.abuse.ch/downloads/hostfile/',
      'https://lists.cyberhost.uk/malware.txt',
      'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt',
      'https://v.firebog.net/hosts/Prigent-Malware.txt',
      'https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt',
      'https://v.firebog.net/hosts/RPiList-Phishing.txt      ',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Malicious.txt',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/ransomware.txt',
    ],
    msfw: [
      'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list',
      'https://v.firebog.net/hosts/Prigent-Adult.txt',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Pornpages.txt',
      //'https://nsfw.oisd.nl/',
    ],
    bets: ['https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/Bets.txt'],
    social: [
      'https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt',
      'https://raw.githubusercontent.com/zangadoprojets/pi-hole-blocklist/main/youtube.txt',
    ],
  }

  private readonly httpClient: HttpClient
  private readonly batchSize: number = 10000
  private readonly maxConcurrentDownloads: number = 3
  private readonly fetchRetries: number = 5
  private readonly fetchRetryDelay: number = 2000 // Increased delay

  /**
   * Construtor do BlocklistService.
   * @param httpClient - Instância do cliente HTTP (opcional, cria um novo se não fornecido).
   */
  constructor(httpClient: HttpClient = new HttpClient({ timeout: 60000 })) {
    // Increased timeout
    this.httpClient = httpClient
  }

  /**
   * Extrai e processa domínios de um stream, inserindo em lotes.
   * @param stream - Stream de dados da blocklist.
   * @param segment - Nome do segmento.
   * @param existingDomains - Conjunto de domínios existentes (opcional).
   * @returns Número de domínios processados.
   */
  private async processStream(
    stream: Readable,
    segment: string,
    existingDomains?: Set<string>
  ): Promise<number> {
    if (!stream.readable) {
      console.warn(`[BlocklistService] Stream inválido para segmento ${segment}`)
      return 0
    }

    const domains: string[] = []
    let processedCount = 0
    const rl = createInterface({ input: stream })

    try {
      for await (const line of rl) {
        const match = line.match(
          /^(?:0\.0\.0\.0\s+|127\.0\.0\.1\s+)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$/
        )
        if (match) {
          const domain = match[1]
          if (!existingDomains || !existingDomains.has(domain)) {
            domains.push(domain)
            if (domains.length >= this.batchSize) {
              await this.saveBatch(domains, segment)
              processedCount += domains.length
              domains.length = 0 // Clear array
            }
          }
        }
      }

      // Save remaining domains
      if (domains.length > 0) {
        await this.saveBatch(domains, segment)
        processedCount += domains.length
      }
    } finally {
      rl.close()
    }

    return processedCount
  }

  /**
   * Baixa e processa uma blocklist de uma URL usando streaming com retries.
   * @param url - URL da blocklist.
   * @param segment - Nome do segmento.
   * @param existingDomains - Conjunto de domínios existentes (opcional).
   * @returns Número de domínios processados.
   */
  private async fetchList(
    url: string,
    segment: string,
    existingDomains?: Set<string>
  ): Promise<number> {
    for (let attempt = 1; attempt <= this.fetchRetries; attempt++) {
      try {
        const response = await this.httpClient.get(url, { responseType: 'stream' })
        const stream = response!.data as Readable
        if (!stream.readable) {
          throw new Error('Stream inválido retornado pela requisição')
        }
        const processedCount = await this.processStream(stream, segment, existingDomains)
        console.log(
          `[BlocklistService] Processados ${processedCount} domínios de ${url} (Tentativa ${attempt})`
        )
        return processedCount
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Erro desconhecido'
        const isLastAttempt = attempt === this.fetchRetries

        console.error(
          `[BlocklistService] Erro ao processar ${url} (Tentativa ${attempt}/${this.fetchRetries}): ${errorMessage}`
        )

        if (!isLastAttempt) {
          await new Promise((resolve) => setTimeout(resolve, this.fetchRetryDelay))
          continue
        }

        console.error(`[BlocklistService] Falha após ${this.fetchRetries} tentativas: ${url}`)
        return 0
      }
    }

    return 0
  }

  /**
   * Obtém domínios existentes no banco para um segmento.
   * @param segment - Nome do segmento.
   * @returns Conjunto de domínios existentes.
   */
  private async getExistingDomains(segment: string): Promise<Set<string>> {
    const result = await BlockList.query().where('segment', segment).select('url')
    return new Set(result.map((record) => record.url))
  }

  /**
   * Consolida listas de um segmento e salva no banco de dados.
   * @param urls - Lista de URLs do segmento.
   * @param segment - Nome do segmento.
   */
  private async consolidateSegment(urls: string[], segment: string): Promise<void> {
    const existingDomains = await this.getExistingDomains(segment)

    // Processa URLs em lotes para limitar conexões simultâneas
    for (let i = 0; i < urls.length; i += this.maxConcurrentDownloads) {
      const batchUrls = urls.slice(i, i + this.maxConcurrentDownloads)
      await Promise.all(batchUrls.map((url) => this.fetchList(url, segment, existingDomains)))
    }

    console.log(`Segmento ${segment} concluído.`)
  }

  /**
   * Salva um lote de domínios no banco de dados.
   * @param domains - Lista de domínios a salvar.
   * @param segment - Nome do segmento.
   */
  private async saveBatch(domains: string[], segment: string): Promise<void> {
    if (domains.length === 0) return

    const records = domains.map((domain) => ({
      url: domain,
      segment,
    }))

    const trx = await db.transaction()
    try {
      await BlockList.createMany(records, { client: trx })
      console.log(`Segmento ${segment}: ${records.length} novos domínios salvos.`)
      await trx.commit()
    } catch (error) {
      await trx.rollback()
      console.error(
        `[BlocklistService] Erro ao salvar domínios no segmento ${segment}: ${error instanceof Error ? error.message : 'Erro desconhecido'}`
      )
      throw error
    }
  }

  /**
   * Processa todas as blocklists e salva no banco de dados.
   */
  public async consolidateAll(): Promise<void> {
    for (const [segment, urls] of Object.entries(this.blockLists)) {
      console.log(`Processando segmento: ${segment}`)
      await this.consolidateSegment(urls, segment)
    }
    console.log('Consolidação concluída.')
  }
}
