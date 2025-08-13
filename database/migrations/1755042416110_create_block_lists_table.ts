import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'block_lists'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.increments('id')

      table.string('url', 512).notNullable().index()
      table.string('segment', 64).notNullable()

      table.unique(['url', 'segment'])

      table.timestamp('created_at')
      table.timestamp('updated_at')
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
