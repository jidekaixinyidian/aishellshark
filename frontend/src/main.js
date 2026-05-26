import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import TrafficList from './views/TrafficList.vue'
import CaptureControl from './views/CaptureControl.vue'
import AIAnalysis from './views/AIAnalysis.vue'
import Reports from './views/Reports.vue'
import PacketsView from './views/PacketsView.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/traffic', component: TrafficList },
  { path: '/capture', component: CaptureControl },
  { path: '/packets', component: PacketsView },
  { path: '/ai', component: AIAnalysis },
  { path: '/reports', component: Reports },
]

const router = createRouter({ history: createWebHistory(), routes })
const app = createApp(App)
app.use(router)
app.mount('#app')
