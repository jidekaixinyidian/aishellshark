<template>
  <div>
    <h1 style="margin-bottom:20px">流量列表</h1>
    <div class="toolbar">
      <button class="btn btn-primary btn-sm" @click="refresh">刷新</button>
      <button class="btn btn-sm" style="margin-left:4px" @click="seed">生成演示数据</button>
      <select v-model="levelFilter" @change="filter"><option value="">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select>
      <span style="font-size:13px;color:#888">共 {{ total }} 条</span>
    </div>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>时间</th><th>源IP</th><th>目的IP</th><th>方法</th><th>URL</th><th>威胁</th><th>评分</th><th>类型</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="s in items" :key="s.session_id">
            <td>{{ s.timestamp?.slice(11,19) }}</td><td>{{ s.src_ip }}</td><td>{{ s.dst_ip }}</td><td>{{ s.method }}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ s.uri }}</td>
            <td><span class="badge" :class="'badge-'+s.threat_level">{{ s.threat_level }}</span></td>
            <td>{{ s.threat_score }}</td><td>{{ s.webshell_type }}</td>
            <td><button class="btn btn-sm btn-primary" @click="viewDetail(s.session_id)">详情</button>
                <button class="btn btn-sm" style="margin-left:4px" @click="decrypt(s.session_id)">解密</button>
                <button class="btn btn-sm" style="margin-left:4px;background:#6a1b9a;color:#fff" @click="aiAnalyze(s.session_id)">AI分析</button></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="pagination" v-if="total > pageSize">
      <button :disabled="page<=1" @click="page--;load()">上一页</button>
      <span>{{ page }}/{{ totalPages }}</span>
      <button :disabled="page>=totalPages" @click="page++;load()">下一页</button>
    </div>
    <div class="card" v-if="detail">
      <h2>会话详情 {{ detail.session?.session_id?.slice(0,8) }}...</h2>
      <pre style="font-size:12px;background:#f5f5f5;padding:12px;border-radius:4px;max-height:400px;overflow:auto">{{ JSON.stringify(detail, null, 2) }}</pre>
    </div>
  </div>
</template>

<script>
import { listSessions, getSession, decryptSession, seedDemo } from '../api/index.js'
export default {
  data() { return { items: [], total: 0, page: 1, pageSize: 20, levelFilter: '', detail: null } },
  computed: { totalPages() { return Math.ceil(this.total / this.pageSize) } },
  mounted() { this.load() },
  methods: {
    async load() {
      const r = await listSessions(this.page, this.pageSize, this.levelFilter)
      this.items = r.data.data?.items || []
      this.total = r.data.data?.total || 0
    },
    filter() { this.page = 1; this.load() },
    refresh() { this.load() },
    async seed() {
      await seedDemo()
      this.load()
    },
    async viewDetail(id) {
      const r = await getSession(id)
      this.detail = r.data.data
    },
    async decrypt(id) {
      await decryptSession(id)
      alert('解密完成，请查看详情')
    },
    async aiAnalyze(id) {
      this.$router.push('/ai')
    }
  }
}
</script>
