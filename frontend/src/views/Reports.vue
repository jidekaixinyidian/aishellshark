<template>
  <div>
    <h1 style="margin-bottom:20px">报告管理</h1>
    <div class="card">
      <h2>生成报告</h2>
      <div class="toolbar">
        <select v-model="format"><option value="html">HTML</option><option value="csv">CSV</option><option value="jsonl">JSONL</option></select>
        <button class="btn btn-primary" @click="generate">生成报告</button>
      </div>
      <p v-if="genResult" style="margin-top:8px;color:#1976d2">报告已生成: {{ genResult.filename }} ({{ (genResult.size/1024).toFixed(1) }} KB)</p>
    </div>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>文件名</th><th>大小</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="r in reports" :key="r.filename">
            <td>{{ r.filename }}</td><td>{{ (r.size/1024).toFixed(1) }} KB</td>
            <td>{{ r.created_at?.replace('T',' ') }}</td>
            <td><a class="btn btn-sm btn-primary" :href="'/api/report/download/'+r.filename" download>下载</a></td>
          </tr>
        </tbody>
      </table>
      <p v-if="!reports.length" style="padding:20px;color:#999;text-align:center">暂无报告</p>
    </div>
  </div>
</template>

<script>
import { listSessions, generateReport, listReports } from '../api/index.js'
export default {
  data() { return { format: 'html', reports: [], genResult: null } },
  mounted() { this.load() },
  methods: {
    async load() {
      const r = await listReports()
      this.reports = r.data.data || []
    },
    async generate() {
      const sr = await listSessions(1, 1000)
      const ids = (sr.data.data?.items || []).map(s => s.session_id)
      if (!ids.length) { alert('无会话数据'); return }
      const r = await generateReport({ session_ids: ids, format: this.format })
      this.genResult = r.data.data
      this.load()
    }
  }
}
</script>
