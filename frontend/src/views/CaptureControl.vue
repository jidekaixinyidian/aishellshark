<template>
  <div>
    <h1 style="margin-bottom:20px">抓包控制</h1>

    <div class="card">
      <h2>网卡选择与配置</h2>
      <div class="toolbar">
        <select v-model="interface_" style="min-width:300px">
          <option value="">自动选择最优网卡</option>
          <option v-for="i in interfaces" :key="i.name" :value="i.name">
            {{ i.name }} {{ i.description ? '('+i.description+')' : '' }} {{ i.ipv4 ? '['+i.ipv4+']' : '' }}
          </option>
        </select>
        <button class="btn btn-sm btn-primary" @click="refreshInterfaces">刷新网卡</button>
      </div>
      <div v-if="selectedIface" style="margin-top:8px;font-size:12px;color:#666;background:#f8f9fa;padding:8px 12px;border-radius:4px">
        <span>MAC: {{ selectedIface.mac || '-' }} | </span>
        <span>状态: {{ selectedIface.status }} | </span>
        <span>{{ selectedIface.is_virtual ? '虚拟网卡' : '物理网卡' }} | </span>
        <span>{{ selectedIface.is_loopback ? '回环接口' : '' }}</span>
      </div>
      <div class="toolbar" style="margin-top:12px">
        <input v-model="bpf" placeholder="BPF过滤器 (如 port 80 or host 192.168.1.1)" style="flex:1;min-width:250px" />
        <button class="btn btn-primary" @click="start" :disabled="running">▶ 启动抓包</button>
        <button class="btn btn-danger" @click="stop" :disabled="!running">■ 停止抓包</button>
      </div>
    </div>

    <div class="card">
      <h2>离线PCAP分析</h2>
      <div class="toolbar">
        <input type="file" accept=".pcap,.pcapng" @change="onFileChange" />
        <button class="btn btn-primary" @click="uploadAndAnalyze" :disabled="!file">上传并分析</button>
      </div>
      <div v-if="pcapProgress" style="margin-top:8px;font-size:13px;color:#1976d2">分析中: {{ pcapProgress }} 包</div>
      <p v-if="pcapResult" style="margin-top:8px;color:#1976d2">分析完成: {{ pcapResult.total }} 个会话</p>
    </div>

    <div class="card">
      <h2>实时状态</h2>
      <div class="stat-grid" style="margin-top:8px">
        <div class="stat-card"><div class="stat-value">{{ statusText }}</div><div class="stat-label">状态</div></div>
        <div class="stat-card"><div class="stat-value">{{ status.packets_captured }}</div><div class="stat-label">已捕获包</div></div>
        <div class="stat-card"><div class="stat-value">{{ status.sessions_detected }}</div><div class="stat-label">检测会话</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#d32f2f">{{ status.threats_found }}</div><div class="stat-label">发现威胁</div></div>
      </div>
      <div v-if="status.interface" style="margin-top:8px;font-size:12px;color:#888">
        当前接口: {{ status.interface }} | 过滤器: {{ status.filter || '(无)' }}
        <span v-if="status.elapsed_seconds"> | 已运行: {{ Math.floor(status.elapsed_seconds/60) }}分{{ Math.floor(status.elapsed_seconds%60) }}秒</span>
      </div>
    </div>

    <div class="card" v-if="interfaces.length">
      <h2>可用网卡列表</h2>
      <div style="overflow-x:auto">
        <table>
          <thead><tr><th>名称</th><th>描述</th><th>IPv4</th><th>MAC</th><th>状态</th><th>类型</th></tr></thead>
          <tbody>
            <tr v-for="i in interfaces" :key="i.name" :style="i.status==='up'&&!i.is_virtual ? 'background:#f0fff0' : ''">
              <td><strong>{{ i.name }}</strong></td>
              <td style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ i.description }}</td>
              <td>{{ i.ipv4 || '-' }}</td>
              <td style="font-size:12px">{{ i.mac || '-' }}</td>
              <td><span class="badge" :class="i.status==='up'?'badge-low':'badge-medium'">{{ i.status }}</span></td>
              <td style="font-size:12px">{{ i.is_virtual ? '虚拟' : '物理' }}{{ i.is_loopback ? '/回环' : '' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
import { getStatus, startCapture, stopCapture, getInterfaces, uploadPcap, analyzePcap } from '../api/index.js'
export default {
  data() {
    return { interface_: '', bpf: '', interfaces: [], status: {}, file: null, pcapResult: null, pcapProgress: null, poll: null }
  },
  computed: {
    running() { return this.status.status === 'running' },
    statusText() { return { idle:'空闲', running:'运行中', stopped:'已停止', error:'错误' }[this.status.status] || '未知' },
    selectedIface() { return this.interfaces.find(i => i.name === this.interface_) || null }
  },
  async mounted() {
    await this.refreshAll()
    this.poll = setInterval(async () => {
      const r = await getStatus(); this.status = r.data.data || {}
    }, 2000)
  },
  beforeUnmount() { clearInterval(this.poll) },
  methods: {
    async refreshAll() {
      const [sr, ir] = await Promise.all([getStatus(), getInterfaces()])
      this.status = sr.data.data || {}
      this.interfaces = (ir.data.data || []).sort((a, b) => {
        if (a.is_loopback) return 1; if (b.is_loopback) return -1
        if (a.is_virtual && !b.is_virtual) return 1; if (!a.is_virtual && b.is_virtual) return -1
        if (a.status === 'up' && b.status !== 'up') return -1
        if (a.status !== 'up' && b.status === 'up') return 1
        return 0
      })
      if (!this.interface_ && this.interfaces.length) {
        const best = this.interfaces.find(i => i.status==='up' && !i.is_loopback && !i.is_virtual && i.ipv4)
        if (best) this.interface_ = best.name
      }
    },
    async refreshInterfaces() {
      const ir = await getInterfaces(); this.interfaces = ir.data.data || []
    },
    async start() {
      await startCapture({ interface: this.interface_, bpf_filter: this.bpf })
    },
    async stop() { await stopCapture() },
    onFileChange(e) { this.file = e.target.files[0]; this.pcapResult = null; this.pcapProgress = null },
    async uploadAndAnalyze() {
      if (!this.file) return
      this.pcapProgress = '上传中...'
      const up = await uploadPcap(this.file)
      const path = up.data.data.path
      this.pcapProgress = '分析中...'
      const ar = await analyzePcap(path)
      this.pcapResult = ar.data.data
      this.pcapProgress = null
    }
  }
}
</script>
