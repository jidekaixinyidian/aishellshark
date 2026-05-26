<template>
  <div>
    <h1 style="margin-bottom:20px">仪表盘</h1>
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-value">{{ stats.total_sessions }}</div><div class="stat-label">总会话</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#d32f2f">{{ high }}</div><div class="stat-label">高危</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#ff9800">{{ stats.threat_distribution?.medium || 0 }}</div><div class="stat-label">中危</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#888">{{ stats.threat_distribution?.low || 0 }}</div><div class="stat-label">低危</div></div>
    </div>
    <div class="card" style="margin-top:20px">
      <h2>抓包状态</h2>
      <p>状态: <strong>{{ captureStatus }}</strong></p>
      <p v-if="status.interface">接口: {{ status.interface }}</p>
      <p>已捕获: {{ status.packets_captured }} 包 | 威胁: {{ status.threats_found }}</p>
    </div>
    <div class="card">
      <h2>最近流量</h2>
      <table v-if="recent.length">
        <thead><tr><th>时间</th><th>源IP</th><th>方法</th><th>URL</th><th>威胁</th></tr></thead>
        <tbody>
          <tr v-for="s in recent" :key="s.session_id">
            <td>{{ s.timestamp?.slice(11,19) }}</td><td>{{ s.src_ip }}</td><td>{{ s.method }}</td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ s.uri }}</td>
            <td><span class="badge" :class="'badge-'+s.threat_level">{{ s.threat_level }}</span></td>
          </tr>
        </tbody>
      </table>
      <p v-else style="color:#999">暂无数据</p>
    </div>
  </div>
</template>

<script>
import { getStatus, listSessions, getStats } from '../api/index.js'
export default {
  data() { return { status: {}, stats: {}, recent: [] } },
  computed: {
    high() { return (this.stats.threat_distribution?.critical || 0) + (this.stats.threat_distribution?.high || 0) },
    captureStatus() { return { idle:'空闲', running:'运行中', stopped:'已停止', error:'错误' }[this.status.status] || '未知' },
  },
  async mounted() {
    const [sr, ss, lr] = await Promise.all([getStatus(), getStats(), listSessions(1, 10)])
    this.status = sr.data.data || {}
    this.stats = ss.data.data || {}
    this.recent = lr.data.data?.items || []
  }
}
</script>
