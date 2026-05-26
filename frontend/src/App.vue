<template>
  <div class="app">
    <nav class="nav">
      <div class="nav-brand">ShellShark</div>
      <router-link class="nav-link" to="/">仪表盘</router-link>
      <router-link class="nav-link" to="/capture">抓包控制</router-link>
      <router-link class="nav-link" to="/traffic">流量列表</router-link>
      <router-link class="nav-link" to="/packets">数据包</router-link>
      <router-link class="nav-link" to="/ai">AI分析</router-link>
      <router-link class="nav-link" to="/reports">报告</router-link>
    </nav>
    <main class="main"><router-view /></main>
  </div>
</template>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #333; }
.app { display: flex; min-height: 100vh; }
.nav { width: 200px; background: #1a1a2e; color: #fff; padding: 20px 0; display: flex; flex-direction: column; }
.nav-brand { font-size: 20px; font-weight: bold; padding: 0 20px 24px; border-bottom: 1px solid #333; margin-bottom: 12px; }
.nav-link { color: #b0b0c0; text-decoration: none; padding: 10px 20px; font-size: 14px; transition: .2s; }
.nav-link:hover, .nav-link.router-link-active { color: #fff; background: rgba(255,255,255,.1); }
.main { flex: 1; padding: 24px; overflow-y: auto; }
.card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
.card h2 { font-size: 16px; margin-bottom: 12px; color: #1a1a2e; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f8f9fa; font-weight: 600; color: #555; }
tr:hover { background: #f5f5ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-critical { background: #d32f2f; color: #fff; }
.badge-high { background: #f44336; color: #fff; }
.badge-medium { background: #ff9800; color: #fff; }
.badge-low { background: #e0e0e0; color: #555; }
.badge-clean { background: #c8e6c9; color: #2e7d32; }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border: none; border-radius: 6px; font-size: 13px; cursor: pointer; transition: .2s; }
.btn-primary { background: #1976d2; color: #fff; }
.btn-primary:hover { background: #1565c0; }
.btn-danger { background: #d32f2f; color: #fff; }
.btn-danger:hover { background: #c62828; }
.btn-sm { padding: 4px 10px; font-size: 12px; }
input, select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; }
input:focus, select:focus { outline: none; border-color: #1976d2; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
.stat-card { background: #fff; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
.stat-value { font-size: 28px; font-weight: bold; color: #1a1a2e; }
.stat-label { font-size: 12px; color: #888; margin-top: 4px; }
.toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
.pagination { display: flex; gap: 8px; align-items: center; justify-content: center; margin-top: 16px; font-size: 13px; }
.pagination button { padding: 4px 12px; border: 1px solid #ddd; border-radius: 4px; background: #fff; cursor: pointer; }
.pagination button:disabled { opacity: .5; cursor: default; }
</style>
