import axios, { AxiosInstance, AxiosResponse } from 'axios'

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
class HttpClient {
  private readonly axiosInstance: AxiosInstance
  private readonly retries: number
  private readonly retryDelay: number

  /**
   * Construtor do HttpClient.
   * @param options - Configurações opcionais (timeout, retries, retryDelay).
   */
  constructor(options: HttpClientOptions = {}) {
    this.axiosInstance = axios.create({
      timeout: options.timeout ?? 10000,
    })
    this.retries = options.retries ?? 3
    this.retryDelay = options.retryDelay ?? 1000
  }

  /**
   * Realiza uma requisição GET com retries automáticos.
   * @param url - URL da requisição.
   * @returns Resposta da requisição ou string vazia em caso de erro.
   * @throws Error se todas as tentativas falharem.
   */
  public async get(url: string): Promise<string> {
    for (let attempt = 1; attempt <= this.retries; attempt++) {
      try {
        const response: AxiosResponse<string> = await this.axiosInstance.get(url)
        console.log(`[HttpClient] Sucesso: ${url} (Tentativa ${attempt})`)
        return response.data
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
        return ''
      }
    }

    return ''
  }
}

export default HttpClient
