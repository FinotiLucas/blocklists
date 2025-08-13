import type { HttpContext } from '@adonisjs/core/http'
import queue from '@rlanz/bull-queue/services/main'
import UpdateBlockListJob from '../jobs/update_block_list_job.js'
export default class BlockListsController {
  async get({ response }: HttpContext) {
    try {
      response.status(200).send('Consolidação concluída.')
    } catch (error) {
      response.badRequest(error)
    }
  }

  async update({ response }: HttpContext) {
    try {
      queue.dispatch(UpdateBlockListJob, undefined, {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
      })
      response.status(200).send('Consolidação concluída.')
    } catch (error) {
      response.badRequest(error)
    }
  }
}
