import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export function getStatus() { return api.get('/status') }
export function startCapture(data) { return api.post('/capture/start', data) }
export function stopCapture() { return api.post('/capture/stop') }
export function getInterfaces() { return api.get('/interfaces') }
export function uploadPcap(file) {
  const fd = new FormData(); fd.append('file', file)
  return api.post('/capture/upload', fd)
}
export function analyzePcap(path) { return api.post('/analyze/pcap', null, { params: { filepath: path } }) }
export function listSessions(page = 1, size = 20, level = '') { return api.get('/sessions', { params: { page, page_size: size, level } }) }
export function seedDemo() { return api.post('/demo/seed') }
export function getSession(id) { return api.get(`/sessions/${id}`) }
export function analyzeAI(data) { return api.post('/analyze/ai', data) }
export function decryptSession(id) { return api.post(`/decrypt/${id}`) }
export function generateReport(data) { return api.post('/report/generate', data) }
export function listReports() { return api.get('/reports') }
export function getStats() { return api.get('/stats') }

export default api
