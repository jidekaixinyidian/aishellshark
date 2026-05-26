<template>
  <div>
    <h1 style="margin-bottom:20px">AI 智能分析</h1>

    <div class="card">
      <div class="toolbar">
        <select v-model="provider" style="padding:4px 8px;border:1px solid #ccc;border-radius:4px">
          <option value="">默认(DeepSeek)</option>
          <option value="openai">OpenAI</option>
          <option value="deepseek">DeepSeek</option>
          <option value="claude">Claude</option>
          <option value="qwen">通义千问</option>
          <option value="ollama">Ollama</option>
        </select>
        <button class="btn btn-primary btn-sm" @click="loadSessions">加载会话列表</button>
      </div>

      <div v-if="sessions.length" class="table-wrap" style="margin-top:8px">
        <table>
          <thead>
            <tr>
              <th style="width:36px"><input type="checkbox" :checked="allSelected" @change="toggleAll" /></th>
              <th>时间</th>
              <th>源IP</th>
              <th>方法</th>
              <th>URI</th>
              <th>威胁</th>
              <th>类型</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in sessions" :key="s.session_id" :class="{ 'row-selected': selected.has(s.session_id) }">
              <td><input type="checkbox" :checked="selected.has(s.session_id)" @change="toggle(s.session_id)" /></td>
              <td style="font-size:11px;font-family:monospace">{{ s.timestamp?.slice(11,19) }}</td>
              <td style="font-size:12px;font-family:monospace">{{ s.src_ip }}</td>
              <td><span :style="s.method==='POST'?'color:#d32f2f;font-weight:600':s.method==='GET'?'color:#1976d2':''">{{ s.method }}</span></td>
              <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">{{ s.uri }}</td>
              <td><span class="badge" :class="'badge-'+s.threat_level" style="font-size:10px">{{ s.threat_level }}</span></td>
              <td style="font-size:11px;color:#888">{{ s.webshell_type }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else style="color:#999;margin-top:8px">暂无会话，请先加载或抓包</p>

      <div v-if="selected.size" class="toolbar" style="margin-top:12px">
        <button class="btn btn-primary" @click="runAI" :disabled="analyzing">
          {{ analyzing ? `分析中 (${analyzedCount}/${selected.size})...` : `AI 分析选中 (${selected.size})` }}
        </button>
        <span v-if="analyzing" style="font-size:12px;color:#666;margin-left:8px">请耐心等待，每个会话约需 3-10 秒</span>
      </div>
    </div>

    <div v-if="error" class="card" style="background:#fff5f5;border:1px solid #ffcdd2">
      <p style="color:#c62828;font-size:13px">{{ error }}</p>
    </div>

    <div v-if="results.length" class="card" style="margin-top:16px">
      <h2>分析结果 <span style="font-size:13px;color:#888;font-weight:400">({{ results.length }} 条)</span></h2>
      <div v-for="r in results" :key="r.session_id" class="result-item" :class="'result-'+r.threat_level">
        <div class="result-header">
          <span class="badge" :class="'badge-'+r.threat_level">{{ r.threat_level }}</span>
          <strong :style="{ color: r.is_webshell ? '#d32f2f' : '#2e7d32' }">{{ r.is_webshell ? '检测到 WebShell' : '未发现威胁' }}</strong>
          <span style="font-size:12px;color:#666;margin-left:8px">
            {{ r.tool_type }} · 置信度 {{ (r.confidence * 100).toFixed(1) }}%
          </span>
          <span style="font-size:11px;color:#999;margin-left:auto">会话 {{ r.session_id?.slice(0,8) }}...</span>
        </div>
        <div v-if="r.attack_intent && r.attack_intent !== '未知'" style="margin-top:6px;font-size:13px">
          <strong>意图:</strong> {{ r.attack_intent }}
        </div>
        <div v-if="r.commands && r.commands.length" style="margin-top:4px;font-size:12px">
          <strong>命令:</strong>
          <code style="background:#f5f5f5;padding:1px 4px;border-radius:2px;margin:0 2px" v-for="c in r.commands" :key="c">{{ c }}</code>
        </div>
        <div v-if="r.payload" style="margin-top:4px">
          <details>
            <summary style="font-size:12px;color:#666;cursor:pointer">载荷详情</summary>
            <pre style="font-size:11px;background:#f5f5f5;padding:8px;border-radius:4px;margin-top:4px;max-height:120px;overflow:auto;white-space:pre-wrap">{{ r.payload }}</pre>
          </details>
        </div>
        <div v-if="r.recommendations && r.recommendations.length" style="margin-top:6px;font-size:12px;color:#1976d2">
          <strong>建议:</strong>
          <ul style="margin:4px 0 0 16px">
            <li v-for="rec in r.recommendations" :key="rec">{{ rec }}</li>
          </ul>
        </div>
        <div v-if="r.raw_response" style="margin-top:6px">
          <details>
            <summary style="font-size:11px;color:#999;cursor:pointer">原始 AI 响应</summary>
            <pre style="font-size:10px;background:#fafafa;padding:8px;border-radius:4px;margin-top:4px;max-height:200px;overflow:auto;white-space:pre-wrap">{{ r.raw_response }}</pre>
          </details>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { listSessions, analyzeAI } from '../api/index.js'
export default {
  data() {
    return {
      sessions: [],
      selected: new Set(),
      results: [],
      analyzing: false,
      analyzedCount: 0,
      provider: '',
      error: '',
    }
  },
  computed: {
    allSelected() {
      return this.sessions.length > 0 && this.selected.size === this.sessions.length
    },
  },
  mounted() {
    this.loadSessions()
  },
  methods: {
    async loadSessions() {
      try {
        const r = await listSessions(1, 100)
        this.sessions = r.data.data?.items || []
        this.selected = new Set()
        this.results = []
        this.error = ''
      } catch (e) {
        this.error = '加载会话失败: ' + (e.response?.data?.error || e.message)
      }
    },
    toggle(sid) {
      const s = new Set(this.selected)
      if (s.has(sid)) s.delete(sid); else s.add(sid)
      this.selected = s
    },
    toggleAll() {
      if (this.allSelected) {
        this.selected = new Set()
      } else {
        this.selected = new Set(this.sessions.map(s => s.session_id))
      }
    },
    async runAI() {
      if (!this.selected.size) return
      this.analyzing = true
      this.analyzedCount = 0
      this.results = []
      this.error = ''
      try {
        const r = await analyzeAI({
          session_ids: Array.from(this.selected),
          provider: this.provider || undefined,
        })
        this.results = r.data.data || []
        this.analyzedCount = this.results.length
      } catch (e) {
        this.error = 'AI 分析失败: ' + (e.response?.data?.error || e.message)
      }
      this.analyzing = false
    },
  },
}
</script>

<style scoped>
.result-item {
  border: 1px solid #eee;
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 8px;
  transition: border-color 0.2s;
}
.result-item:hover { border-color: #ccc; }
.result-high { border-left: 3px solid #d32f2f; }
.result-medium { border-left: 3px solid #f57c00; }
.result-low { border-left: 3px solid #1976d2; }
.result-clean { border-left: 3px solid #2e7d32; }
.result-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.row-selected { background: #e8f5e9; }
.table-wrap { overflow-x: auto; }
</style>
