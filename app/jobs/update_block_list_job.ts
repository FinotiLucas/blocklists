import BlocklistService from '#services/blocklist_service'
import { Job } from '@rlanz/bull-queue'

export default class UpdateBlockListJob extends Job {
  // This is the path to the file that is used to create the job
  static get $$filepath() {
    return import.meta.url
  }

  private blocklistService: BlocklistService = new BlocklistService()

  /**
   * Base Entry point
   */
  async handle() {
    await this.blocklistService.consolidateAll()
  }

  /**
   * This is an optional method that gets called when the retries has exceeded and is marked failed.
   */
  async rescue() {}
}
