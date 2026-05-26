<template>
  <div>
    <h1 style="margin-bottom:20px">数据包列表</h1>

    <div class="wireshark-filterbar">
      <input ref="filterInput" v-model="filterText" class="ws-filter-input"
             placeholder="显示过滤器，例如: ip==192.168.1.1  port==80  method==POST  threat>50  type==chopper  uri contains /upload"
             @keyup.enter="applyFilter" @keyup="onFilterKeyup" />
      <button class="btn btn-sm" style="background:#2e7d32;color:#fff" @click="applyFilter">应用</button>
      <button class="btn btn-sm btn-primary" @click="refresh">刷新</button>
      <span style="font-size:12px;color:#888;white-space:nowrap">{{ total }} 个数据包</span>
    </div>

    <div v-if="filterError" style="background:#ffebee;color:#c62828;padding:6px 12px;margin-bottom:8px;border-radius:4px;font-size:12px">
      {{ filterError }}
    </div>

    <div class="card" style="padding:0">
      <div style="overflow-x:auto">
        <table>
          <thead><tr>
            <th style="width:70px">时间</th>
            <th style="width:170px">源地址</th>
            <th style="width:170px">目的地址</th>
            <th style="width:50px">协议</th>
            <th style="width:55px">长度</th>
            <th style="width:50px">方法</th>
            <th>URI</th>
            <th style="width:60px">威胁</th>
            <th style="width:50px">评分</th>
            <th style="width:90px">类型</th>
            <th style="width:50px">操作</th>
          </tr></thead>
          <tbody>
            <tr v-for="p in items" :key="p.packet_id" @click="viewDetail(p.session_id)" style="cursor:pointer">
              <td style="font-size:11px;white-space:nowrap;font-family:monospace">{{ p.timestamp?.slice(11,19) }}</td>
              <td style="font-size:12px;font-family:monospace">{{ p.src_ip }}:{{ p.src_port }}</td>
              <td style="font-size:12px;font-family:monospace">{{ p.dst_ip }}:{{ p.dst_port }}</td>
              <td style="font-size:11px;color:#888">{{ p.protocol }}</td>
              <td style="font-size:11px;font-family:monospace">{{ p.size }}</td>
              <td><span :style="p.method==='POST'?'color:#d32f2f;font-weight:600':p.method==='GET'?'color:#1976d2':''">{{ p.method }}</span></td>
              <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">{{ p.uri }}</td>
              <td><span class="badge" :class="'badge-'+p.threat_level" style="font-size:10px">{{ p.threat_level }}</span></td>
              <td style="font-family:monospace;font-size:12px">{{ p.threat_score }}</td>
              <td style="font-size:12px">{{ p.webshell_type }}</td>
              <td>
                <button class="btn btn-sm btn-primary" style="font-size:11px;padding:2px 8px" @click.stop="viewDetail(p.session_id)">详情</button>
                <button class="btn btn-sm" style="font-size:11px;padding:2px 8px;margin-left:2px;background:#6a1b9a;color:#fff" @click.stop="aiAnalyze(p.session_id)">AI</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="pagination" v-if="total > pageSize">
      <button :disabled="page<=1" @click="page--;load()">上一页</button>
      <span>{{ page }}/{{ totalPages }}</span>
      <button :disabled="page>=totalPages" @click="page++;load()">下一页</button>
    </div>

    <div class="card" v-if="detail" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h2 style="margin:0">数据包详情</h2>
        <button class="btn btn-sm" @click="detail=null">关闭</button>
      </div>
      <pre style="font-size:12px;background:#f5f5f5;padding:12px;border-radius:4px;max-height:500px;overflow:auto">{{ JSON.stringify(detail, null, 2) }}</pre>
    </div>
  </div>
</template>

<script>
import api from '../api/index.js'
export default {
  data() {
    return {
      items: [], total: 0, page: 1, pageSize: 50,
      filterText: '', filterError: '', detail: null,
      filterHistory: [],
    }
  },
  computed: {
    totalPages() { return Math.ceil(this.total / this.pageSize) },
  },
  mounted() {
    const saved = localStorage.getItem('ws_filter')
    if (saved) this.filterText = saved
    this.load()
  },
  methods: {
    async load() {
      this.filterError = ''
      const params = { page: this.page, page_size: this.pageSize }
      if (this.filterText.trim()) params.q = this.filterText.trim()
      try {
        const r = await api.get('/packets', { params })
        this.items = r.data.data?.items || []
        this.total = r.data.data?.total || 0
        localStorage.setItem('ws_filter', this.filterText.trim())
      } catch (e) {
        this.filterError = '加载失败: ' + (e.response?.data?.error || e.message)
      }
    },
    applyFilter() {
      this.page = 1
      this.load()
    },
    refresh() { this.load() },
    onFilterKeyup(e) {
      if (e.key === 'Escape') { this.filterText = ''; this.applyFilter() }
    },
    async viewDetail(sid) {
      if (!sid) return
      try {
        const r = await api.get(`/sessions/${sid}`)
        this.detail = r.data.data
      } catch (e) {
        this.filterError = '获取详情失败: ' + (e.response?.data?.error || e.message)
      }
    },
    aiAnalyze(sid) {
      this.$router.push('/ai')
    },
  },
}
</script>

<style scoped>
.wireshark-filterbar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
  background: #e8f5e9;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px solid #a5d6a7;
}
.ws-filter-input {
  flex: 1;
  padding: 6px 10px;
  border: 1px solid #a5d6a7;
  border-radius: 4px;
  font-size: 13px;
  font-family: monospace;
  background: #fff;
  outline: none;
  transition: border-color .2s;
}
.ws-filter-input:focus {
  border-color: #2e7d32;
  box-shadow: 0 0 0 2px rgba(46,125,50,.2);
}
.ws-filter-input::placeholder {
  color: #999;
  font-size: 12px;
}
</style>
