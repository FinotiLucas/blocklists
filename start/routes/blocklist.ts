import router from '@adonisjs/core/services/router'

const BlockListsController = () => import('#controllers/blocklists_controller')

router
  .group(() => {
    router.get('/lists/:segment', [BlockListsController, 'get']).as('blocklists.get')
    router.post('/lists/update', [BlockListsController, 'update']).as('blocklists.update')
  })
  .as('api')
  .prefix('/api/v1')
