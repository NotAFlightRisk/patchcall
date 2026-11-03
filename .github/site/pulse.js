const tracker = document.getElementById('pulse')
window.plausible.init({ endpoint: new URL('/api/event', tracker.src).href })
