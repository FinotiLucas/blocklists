import axios, { AxiosInstance, AxiosResponse } from 'axios'
import { Readable } from 'node:stream'

/**
 * Interface para opções de configuração do HttpClient.
 */
interface HttpClientOptions {
  timeout?: number
  retries?: number
  retryDelay?: number
}

/**
 * Cliente HTTP para realizar requisições com tratamento de erros.
 */
export default class HttpClient {
  private readonly axiosInstance: AxiosInstance
  private readonly retries: number
  private readonly retryDelay: number

  /**
   * Construtor do HttpClient.
   * @param options - Configurações opcionais (timeout, retries, retryDelay).
   */
  constructor(options: HttpClientOptions = {}) {
    this.axiosInstance = axios.create({
      timeout: options.timeout ?? 60000, // Default to 60 seconds
      headers: {
        Accept: 'text/plain',
      },
    })
    this.retries = options.retries ?? 5 // Increased retries
    this.retryDelay = options.retryDelay ?? 2000 // Increased delay
  }

  /**
   * Realiza uma requisição GET com retries automáticos.
   * @param url - URL da requisição.
   * @param options - Opções de configuração, incluindo responseType.
   * @returns Resposta da requisição ou null em caso de erro.
   */
  public async get(
    url: string,
    options: { responseType?: 'stream' | 'text' } = {}
  ): Promise<AxiosResponse<string | Readable> | null> {
    for (let attempt = 1; attempt <= this.retries; attempt++) {
      try {
        const response = await this.axiosInstance.get<string | Readable>(url, {
          responseType: options.responseType ?? 'text',
          headers: {
            Accept: 'text/plain',
          },
        })
        console.log(`[HttpClient] Sucesso: ${url} (Tentativa ${attempt})`)
        return response
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Erro desconhecido'
        const isLastAttempt = attempt === this.retries

        console.error(
          `[HttpClient] Erro ao baixar ${url} (Tentativa ${attempt}/${this.retries}): ${errorMessage}`
        )

        if (!isLastAttempt) {
          await new Promise((resolve) => setTimeout(resolve, this.retryDelay))
          continue
        }

        console.error(`[HttpClient] Falha após ${this.retries} tentativas: ${url}`)
        return null // Return null instead of invalid Readable
      }
    }

    return null
  }
}
