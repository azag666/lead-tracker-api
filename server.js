<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HotTrack SAAS</title>

    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#020617"/>

    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100%22><text y=%22.9em%22 font-size=%2290%22>⚡️</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif; background-color: #020617; color: #e2e8f0;
            background-image: radial-gradient(circle at 1px 1px, rgba(56, 189, 248, 0.1) 1px, transparent 0);
            background-size: 20px 20px;
        }
        .card {
            background-color: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.2);
            backdrop-filter: blur(12px); transition: all 0.3s ease;
        }
        .form-input, .form-select, .form-date {
            background-color: rgba(30, 41, 59, 0.5); border: 1px solid #334155; color: #cbd5e1;
            transition: all 0.3s ease;
        }
        .form-input:focus, .form-select:focus, .form-date:focus {
            outline: none; border-color: #38bdf8;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.2);
        }
        .form-date::-webkit-calendar-picker-indicator {
            filter: invert(0.6) sepia(1) saturate(5) hue-rotate(180deg);
        }
        .btn {
            background-color: #0ea5e9; color: white; transition: all 0.3s ease;
            box-shadow: 0 0 10px rgba(14, 165, 233, 0.3), inset 0 0 5px rgba(255, 255, 255, 0.1);
            border: 1px solid #38bdf8;
        }
        .btn:hover {
            background-color: #38bdf8; box-shadow: 0 0 20px rgba(56, 189, 248, 0.6);
            transform: translateY(-2px);
        }
        .btn:disabled { background-color: #334155; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-red { background-color: #7f1d1d; border-color: #b91c1c; box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
        .btn-red:hover { background-color: #991b1b; box-shadow: 0 0 20px rgba(239, 68, 68, 0.6); }
        .btn-green { background-color: #047857; border-color: #059669; box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
        .btn-green:hover { background-color: #059669; box-shadow: 0 0 20px rgba(16, 185, 129, 0.6); }
        .btn-secondary { background-color: #334155; border-color: #475569; box-shadow: none; }
        .btn-secondary:hover { background-color: #475569; transform: translateY(-2px); }
        .btn-filter { background-color: transparent; border: 1px solid #334155; color: #94a3b8; }
        .btn-filter:hover { background-color: #1e293b; border-color: #38bdf8; color: #e2e8f0; }
        .btn-filter.active { background-color: rgba(14, 165, 233, 0.1); border-color: #0ea5e9; color: white; font-weight: 600; }
        .nav-link { color: #94a3b8; border-left: 3px solid transparent; cursor: pointer; transition: all 0.3s ease; }
        .nav-link:hover { background-color: rgba(56, 189, 248, 0.05); border-left-color: #38bdf8; color: #e2e8f0; }
        .nav-link.active { background-color: rgba(14, 165, 233, 0.1); border-left-color: #0ea5e9; color: white; font-weight: 600; }
        .modal { display: none; }
        .modal.active { display: flex; align-items: center; justify-content: center; position: fixed; z-index: 50; inset: 0; background-color: rgba(0,0,0,0.7); backdrop-filter: blur(8px); }
        .animate-fade-in { animation: fadeIn 0.5s ease-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .table-custom th, .table-custom td { padding: 0.75rem; border-bottom: 1px solid #334155; text-align: left; }
        .status-indicator { font-size: 0.75rem; font-weight: 500; padding: 0.125rem 0.5rem; border-radius: 9999px; display: inline-block; margin-left: 0.75rem; vertical-align: middle; }
        .status-indicator.success { background-color: rgba(74, 222, 128, 0.1); color: #4ade80; border: 1px solid rgba(74, 222, 128, 0.2); }
        .status-indicator.failure { background-color: rgba(248, 113, 113, 0.1); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.2); }
        .status-indicator.unknown { background-color: rgba(100, 116, 139, 0.1); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.2); }
        .status-indicator.testing { background-color: rgba(56, 189, 248, 0.1); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.2); }
        .tab-button { background-color: transparent; border: 1px solid #334155; color: #94a3b8; padding: 0.5rem 1rem; border-radius: 0.375rem; transition: all 0.3s ease; }
        .tab-button:hover { background-color: #1e293b; color: #e2e8f0; }
        .tab-button.active { background-color: rgba(14, 165, 233, 0.1); border-color: #0ea5e9; color: white; font-weight: 600; }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.5s ease-out; }
    </style>
</head>
<body>
    <div id="app"></div>
    <div id="modal-container"></div>

    <script>
    const App = {
        state: {
            API_BASE_URL: 'https://novaapi-one.vercel.app',
            token: null,
            data: { 
                pixels: [], 
                bots: [], 
                pressels: [], 
                checkouts: [],
                settings: {}, 
                transactions: [],
                dashboard: {}
            },
            currentPage: 'dashboard',
            dateFilter: {
                period: 'all',
                startDate: null,
                endDate: null
            },
            revenueChart: null
        },

        async init() {
            if (window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')) {
                this.state.API_BASE_URL = 'http://localhost:3000';
            }
            this.state.token = localStorage.getItem('hottrack_token');
            const appContainer = document.getElementById('app');
            appContainer.innerHTML = `<div class="flex h-screen items-center justify-center"><p>Carregando...</p></div>`;

            if (this.state.token && this.state.token !== 'undefined' && this.state.token !== null) {
                try {
                    const staticData = await this.apiRequest('/api/dashboard/data');
                    if (staticData) { // Apenas atualiza se houver novos dados
                        this.state.data = { ...this.state.data, ...staticData };
                    }
                    this.renderLayout();
                    this.navigateTo('dashboard');
                } catch (e) { 
                    this.logout(); 
                }
            } else {
                this.renderLogin();
            }
        },

        renderLogin(page = 'login') {
            document.getElementById('app').innerHTML = this.templates.auth(page);
            this.addAuthEventListeners();
        },

        renderLayout() {
            document.getElementById('app').innerHTML = this.templates.layout();
            this.addDashboardEventListeners();
        },
        
        templates: {
            auth(page = 'login') {
                return `<div class="flex items-center justify-center min-h-screen p-4"><div id="auth-forms-container" class="w-full max-w-md">${page === 'login' ? this.loginForm() : this.registerForm()}</div></div>`;
            },
            loginForm() {
                return `
                <div class="card p-8 rounded-2xl shadow-lg animate-fade-in">
                    <h1 class="text-3xl font-bold text-center text-white">Acessar Plataforma</h1>
                    <form id="loginForm" class="space-y-6 mt-8">
                        <div><label class="text-sm font-medium text-gray-400">E-mail</label><input name="email" type="email" required class="form-input w-full p-3 mt-1 rounded-md"></div>
                        <div><label class="text-sm font-medium text-gray-400">Senha</label><input name="password" type="password" required class="form-input w-full p-3 mt-1 rounded-md"></div>
                        <button type="submit" class="btn w-full font-semibold py-3 rounded-md">Entrar</button>
                    </form>
                    <div class="text-center mt-6"><a href="#" id="showRegister" class="text-sm text-sky-400 hover:text-sky-300">Não tem uma conta? Cadastre-se</a></div>
                </div>`;
            },
            registerForm() {
                return `
                <div class="card p-8 rounded-2xl shadow-lg animate-fade-in">
                    <h1 class="text-3xl font-bold text-center text-white">Criar Conta</h1>
                    <form id="registerForm" class="space-y-6 mt-8">
                        <div><label class="text-sm font-medium text-gray-400">Nome</label><input name="name" type="text" required class="form-input w-full p-3 mt-1 rounded-md"></div>
                        <div><label class="text-sm font-medium text-gray-400">E-mail</label><input name="email" type="email" required class="form-input w-full p-3 mt-1 rounded-md"></div>
                        <div><label class="text-sm font-medium text-gray-400">Senha</label><input name="password" type="password" required minlength="8" class="form-input w-full p-3 mt-1 rounded-md"></div>
                        <button type="submit" class="btn w-full font-semibold py-3 rounded-md">Criar Conta</button>
                    </form>
                    <div class="text-center mt-6"><a href="#" id="showLogin" class="text-sm text-sky-400 hover:text-sky-300">Já tem uma conta? Faça Login</a></div>
                </div>`;
            },
            layout() {
                const recuperadorLink = this.state.data.settings.has_recuperador_access 
                    ? `<div data-target="recuperador" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 13.5 12 21m0 0-7.5-7.5M12 21V3" /></svg>Recuperador</div>` 
                    : '';

                return `
                <div class="flex h-screen">
                    <aside class="w-64 card p-4 flex flex-col">
                        <div class="text-center mb-10 flex items-center justify-center gap-2">
                            <svg class="h-8 w-8 text-sky-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>
                            <h1 class="text-2xl font-bold text-white">HotTrack</h1>
                        </div>
                        <nav id="sidebarNav" class="flex flex-col space-y-2">
                            <div data-target="dashboard" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 10v11h18V10M3 10l9-7 9 7M3 10h18" /></svg>Dashboard</div>
                            ${recuperadorLink}
                            <div data-target="checkouts" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h6m3-3.75l-3 3m0 0l-3-3m3 3V15m6 1.125c1.02.392 2.132.526 3.25.526a9.75 9.75 0 000-19.5 9.75 9.75 0 00-3.25.526" /></svg>Criador de Checkout</div>
                            <div data-target="pressels" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>Criador de Pressel</div>
                            <div data-target="pixels" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 12l4.179 2.25M6.429 9.75l5.571 3 5.571-3m0 0l4.179-2.25L12 5.25 7.821 7.5" /></svg>Gerenciar Pixels</div>
                            <div data-target="bots" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>Gerenciar Bots</div>
                            <div data-target="transactions" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 18.75a60.01 60.01 0 0110.875-3.004m-.89 6.002c-.087-.665-.544-1.284-1.2-1.76l-.427-.36a4.5 4.5 0 01-1.272-3.138v-.686m12.446 3.004c-.66.087-1.284.544-1.76 1.2l-.36.427a4.5 4.5 0 01-3.138 1.272h-.686m0-15.558a.75.75 0 00-.75-.75H12a.75.75 0 00-.75.75v.686a4.5 4.5 0 01-1.272 3.138l-.36.427c-.476.66-.544 1.284-.36 1.76M21.75 12a.75.75 0 00-.75-.75H12a.75.75 0 00-.75.75v.686a4.5 4.5 0 01-3.138 1.272l-.36.427c-.476.66-.544 1.284-.36 1.76m0-4.5a.75.75 0 00-.75-.75H12a.75.75 0 00-.75.75v.686a4.5 4.5 0 01-1.272 3.138l-.36.427c-.476.66-.544 1.284-.36 1.76M21.75 12a.75.75 0 00-.75-.75H12a.75.75 0 00-.75.75v.686a4.5 4.5 0 01-3.138 1.272l-.36.427c-.476.66-.544 1.284-.36 1.76" /></svg>Transações</div>
                            <div class="h-px bg-slate-700 my-2"></div>
                            <div data-target="settings" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" /></svg>API PIX</div>
                            <div data-target="integrations" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" /></svg>Integrações</div>
                            <div data-target="documentation" class="nav-link p-3 rounded-lg flex items-center gap-3"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" /></svg>Documentação</div>
                        </nav>
                        <div class="mt-auto"><button id="logoutButton" class="w-full text-gray-400 hover:bg-red-900/50 hover:text-white font-semibold py-2 px-4 rounded-md flex items-center justify-center gap-2"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>Sair</button></div>
                    </aside>
                    <main id="content" class="flex-1 p-8 overflow-y-auto"></main>
                </div>`;
            },
            dateFilterComponent(page) {
                const { period } = App.state.dateFilter;
                return `
                <div id="${page}-date-filter" class="card p-4 rounded-lg mb-6 flex flex-wrap items-center gap-2 text-sm">
                    <span class="font-semibold mr-2">Filtrar por:</span>
                    <button data-period="today" class="btn-filter py-1 px-3 rounded-md ${period === 'today' ? 'active' : ''}">Hoje</button>
                    <button data-period="yesterday" class="btn-filter py-1 px-3 rounded-md ${period === 'yesterday' ? 'active' : ''}">Ontem</button>
                    <button data-period="last7days" class="btn-filter py-1 px-3 rounded-md ${period === 'last7days' ? 'active' : ''}">Últimos 7 dias</button>
                    <button data-period="thisMonth" class="btn-filter py-1 px-3 rounded-md ${period === 'thisMonth' ? 'active' : ''}">Este Mês</button>
                    <div class="flex items-center gap-2 pl-4 border-l border-slate-700 ml-2">
                         <input type="date" id="${page}-start-date" class="form-date p-1 rounded-md text-sm">
                         <span class="text-gray-500">até</span>
                         <input type="date" id="${page}-end-date" class="form-date p-1 rounded-md text-sm">
                         <button id="apply-custom-date-filter-${page}" class="btn-secondary py-1 px-3 rounded-md">Filtrar</button>
                    </div>
                    <button id="clear-date-filter-${page}" class="btn-secondary py-1 px-3 rounded-md ml-auto">Limpar</button>
                </div>`;
            },
            dashboard() {
                return `
                <div class="animate-fade-in">
                    <div class="flex justify-between items-center mb-6">
                        <h1 class="text-3xl font-bold text-white">Painel de Métricas</h1>
                    </div>
                    ${this.dateFilterComponent('dashboard')}
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
                        <div class="card p-6 rounded-lg text-center"><h3 class="text-sm text-gray-400">Cliques na Página</h3><p id="metric-clicks" class="text-4xl font-bold text-sky-400 mt-2">...</p></div>
                        <div class="card p-6 rounded-lg text-center"><h3 class="text-sm text-gray-400">PIX Gerados</h3><p id="metric-generated" class="text-4xl font-bold text-yellow-400 mt-2">...</p></div>
                        <div class="card p-6 rounded-lg text-center"><h3 class="text-sm text-gray-400">Faturamento Total</h3><p id="metric-total-revenue" class="text-4xl font-bold text-sky-400 mt-2">...</p></div>
                        <div class="card p-6 rounded-lg text-center"><h3 class="text-sm text-gray-400">PIX Pagos</h3><p id="metric-paid" class="text-4xl font-bold text-green-400 mt-2">...</p></div>
                        <div class="card p-6 rounded-lg text-center"><h3 class="text-sm text-gray-400">Faturamento Pago</h3><p id="metric-paid-revenue" class="text-4xl font-bold text-green-400 mt-2">...</p></div>
                    </div>
                    <div class="card p-6 rounded-lg mb-8">
                        <h2 class="text-xl font-semibold text-white mb-4">Desempenho de Faturamento</h2>
                        <canvas id="revenueChart" height="100"></canvas>
                    </div>
                    <div class="grid grid-cols-1 gap-8 md:grid-cols-2">
                        <div class="card p-6 rounded-lg"><h2 class="text-xl font-semibold text-white mb-4">Desempenho por Bot</h2><div id="bots-performance-table-container" class="overflow-x-auto"><table class="table-custom w-full text-sm"><thead><tr><th>Bot</th><th>Cliques</th><th>Vendas</th><th>Faturamento</th></tr></thead><tbody id="bots-performance-table"><tr><td colspan="4">Carregando...</td></tr></tbody></table></div></div>
                        <div class="card p-6 rounded-lg"><h2 class="text-xl font-semibold text-white mb-4">Tráfego por Estado</h2><div id="traffic-by-state-table-container" class="overflow-x-auto"><table class="table-custom w-full text-sm"><thead><tr><th>Estado</th><th>Cliques</th></tr></thead><tbody id="traffic-by-state-table"><tr><td colspan="2">Carregando...</td></tr></tbody></table></div></div>
                    </div>
                </div>`;
            },
            pixels() {
                const pixelListHTML = App.state.data.pixels.map(p => `<div class="p-2 bg-slate-900/50 rounded flex justify-between items-center"><span class="text-sm">${p.account_name}</span><button data-id="${p.id}" class="delete-pixel-btn btn btn-red text-xs py-1 px-2">Excluir</button></div>`).join('');
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Gerenciar Pixels</h1>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-semibold mb-4 text-white">Adicionar Pixel</h2>
                            <form id="pixelForm" class="space-y-3"><input name="account_name" placeholder="Nome do Pixel (Ex: Produto Y)" class="form-input w-full p-2 rounded-md" required><input name="pixel_id" placeholder="ID do Pixel da Meta" class="form-input w-full p-2 rounded-md" required><textarea name="meta_api_token" placeholder="Token da API de Conversões" class="form-input w-full p-2 rounded-md" rows="2" required></textarea><button type="submit" class="btn w-full p-2 rounded-md">Adicionar Pixel</button></form>
                        </div>
                        <div class="card p-6 rounded-lg"><h2 class="text-xl font-semibold text-white mb-4">Pixels Salvos</h2><div id="pixel-list" class="space-y-2">${pixelListHTML.length ? pixelListHTML : '<p class="text-gray-500 text-sm">Nenhum pixel salvo.</p>'}</div></div>
                    </div>
                </div>`;
            },
            bots() {
                 const botListHTML = App.state.data.bots.map(b => `
                    <div class="p-3 bg-slate-900/50 rounded flex justify-between items-center">
                        <div>
                            <span class="text-sm font-medium">${b.bot_name}</span>
                            <span id="status-indicator-bot-${b.id}"></span>
                        </div>
                        <div class="space-x-2">
                            <button data-id="${b.id}" class="test-bot-btn btn-green text-xs py-1 px-2">Testar</button>
                            <button data-id="${b.id}" class="delete-bot-btn btn btn-red text-xs py-1 px-2">Excluir</button>
                        </div>
                    </div>`).join('');
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Gerenciar Bots</h1>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-semibold mb-4 text-white">Adicionar Bot</h2>
                            <form id="botForm" class="space-y-3"><input name="bot_name" placeholder="Username do Bot (sem @)" class="form-input w-full p-2 rounded-md" required><input name="bot_token" placeholder="Token do Bot (do BotFather)" class="form-input w-full p-2 rounded-md" required><button type="submit" class="btn w-full p-2 rounded-md">Adicionar Bot</button></form>
                        </div>
                        <div class="card p-6 rounded-lg"><h2 class="text-xl font-semibold text-white mb-4">Bots Salvos</h2><div id="bot-list" class="space-y-2">${botListHTML.length ? botListHTML : '<p class="text-gray-500 text-sm">Nenhum bot salvo.</p>'}</div></div>
                    </div>
                </div>`;
            },
            pressels() {
                const { pixels, bots, pressels } = App.state.data;
                const botOptions = bots.map(b => `<option value="${b.id}">${b.bot_name}</option>`).join('');
                const pixelCheckboxes = pixels.map(p => `<label class="flex items-center space-x-2 text-gray-400 hover:text-white cursor-pointer"><input type="checkbox" name="pixel_ids" value="${p.id}" class="h-4 w-4 bg-slate-700 border-slate-500 rounded text-sky-500 focus:ring-sky-500"><span>${p.account_name}</span></label>`).join('');
                const presselList = pressels.map(pr => `<div class="p-3 card flex justify-between items-center text-sm"><div><p class="font-semibold">${pr.name}</p><p class="text-xs text-gray-400">Bot: ${pr.bot_name}</p></div><div class="space-x-2"><button data-id="${pr.id}" class="generate-pressel-code-btn btn text-xs py-1 px-2">Ver Código</button><button data-id="${pr.id}" class="delete-pressel-btn btn btn-red text-xs py-1 px-2">Excluir</button></div></div>`).join('');
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Criador de Pressel</h1>
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-bold mb-4 text-white">Criar Nova Pressel</h2>
                            <form id="presselForm" class="space-y-4"><input name="name" placeholder="Nome da Pressel (Ex: Campanha Black Friday)" class="form-input w-full p-2 rounded-md" required><input name="white_page_url" type="url" placeholder="URL da Página Branca (Fallback)" class="form-input w-full p-2 rounded-md" required><select name="bot_id" class="form-input w-full p-2 rounded-md" required><option value="">Selecione um Bot</option>${botOptions}</select><div class="card p-3"><p class="font-semibold mb-2">Selecione os Pixels:</p><div class="space-y-2">${pixelCheckboxes.length ? pixelCheckboxes : '<p class="text-gray-500 text-sm">Cadastre um pixel primeiro.</p>'}</div></div><button type="submit" class="btn w-full p-3 rounded-md text-base font-bold">Salvar e Gerar Código</button></form>
                        </div>
                        <div class="card p-6 rounded-lg"><h2 class="text-xl font-bold mb-4 text-white">Pressels Criadas</h2><div id="pressel-list" class="space-y-3">${presselList.length ? presselList : '<p class="text-gray-500 text-sm">Nenhuma pressel criada.</p>'}</div></div>
                    </div>
                </div>`;
            },
            checkouts() {
                const { pixels, checkouts } = App.state.data;
                const pixelCheckboxes = pixels.map(p => `<label class="flex items-center space-x-2 text-gray-400 hover:text-white cursor-pointer"><input type="checkbox" name="pixel_ids" value="${p.id}" class="h-4 w-4 bg-slate-700 border-slate-500 rounded text-sky-500 focus:ring-sky-500"><span>${p.account_name}</span></label>`).join('');
                const checkoutList = checkouts.map(c => `
                    <div class="p-3 card flex justify-between items-center text-sm">
                        <div>
                            <p class="font-semibold">${c.name}</p>
                            <p class="text-xs text-gray-400">Produto: ${c.product_name}</p>
                        </div>
                        <div class="space-x-2">
                            <button data-id="${c.id}" class="generate-checkout-code-btn btn text-xs py-1 px-2">Ver Código</button>
                            <button data-id="${c.id}" class="delete-checkout-btn btn btn-red text-xs py-1 px-2">Excluir</button>
                        </div>
                    </div>`).join('');

                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Criador de Checkout</h1>
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-bold mb-4 text-white">Criar Novo Checkout</h2>
                            <form id="checkoutForm" class="space-y-4">
                                <input name="name" placeholder="Nome Interno do Checkout (Ex: Ebook XYZ)" class="form-input w-full p-2 rounded-md" required>
                                <input name="product_name" placeholder="Nome do Produto (visível ao cliente)" class="form-input w-full p-2 rounded-md" required>
                                <input name="redirect_url" type="url" placeholder="URL de Redirecionamento Pós-Compra (Obrigado/Entrega)" class="form-input w-full p-2 rounded-md" required>
                                
                                <select name="value_type" id="value-type-selector" class="form-select w-full p-2 rounded-md" required>
                                    <option value="fixed">Valor Fixo</option>
                                    <option value="variable">Valor Variável (definido na URL)</option>
                                </select>
                                
                                <div id="fixed-value-container">
                                    <input name="fixed_value_cents" type="number" placeholder="Valor em CENTAVOS (Ex: 1990 para R$19,90)" class="form-input w-full p-2 rounded-md">
                                </div>

                                <div class="card p-3">
                                    <p class="font-semibold mb-2">Selecione os Pixels para este Checkout:</p>
                                    <div class="space-y-2">${pixelCheckboxes.length ? pixelCheckboxes : '<p class="text-gray-500 text-sm">Cadastre um pixel primeiro.</p>'}</div>
                                </div>
                                
                                <button type="submit" class="btn w-full p-3 rounded-md text-base font-bold">Salvar e Gerar Código</button>
                            </form>
                        </div>
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-bold mb-4 text-white">Checkouts Criados</h2>
                            <div id="checkout-list" class="space-y-3">${checkoutList.length ? checkoutList : '<p class="text-gray-500 text-sm">Nenhum checkout criado.</p>'}</div>
                        </div>
                    </div>
                </div>`;
            },
            recuperador() {
                const { bots } = App.state.data;
                const botOptions = bots.map(b => `<option value="${b.id}">${b.bot_name}</option>`).join('');

                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Recuperador de Leads</h1>
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-bold mb-4 text-white">Nova Campanha de Recuperação</h2>
                            <form id="broadcastForm" class="space-y-4">
                                <select name="botId" id="broadcast-bot-selector" class="form-select w-full p-2 rounded-md" required>
                                    <option value="">Selecione o Bot Abandonado</option>
                                    ${botOptions}
                                </select>
                                <textarea name="messageText" class="form-input w-full p-2 rounded-md" rows="8" placeholder="Escreva sua mensagem de reengajamento aqui...&#10;Dica: Use [NomeDoCheckout] para inserir um link de checkout.&#10;Ex: [OfertaEspecial]" required></textarea>
                                <button type="submit" class="btn w-full p-3 font-bold">Disparar Campanha</button>
                            </form>
                        </div>
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-bold mb-4 text-white">Histórico de Campanhas</h2>
                            <div id="broadcast-history" class="space-y-3 overflow-y-auto max-h-96">
                                <p class="text-gray-500 text-sm">Selecione um bot para ver o histórico.</p>
                            </div>
                        </div>
                    </div>
                </div>`;
            },
            transactions() {
                return `
                <div class="animate-fade-in">
                    <div class="flex justify-between items-center mb-6"><h1 class="text-3xl font-bold text-white">Histórico de Transações</h1></div>
                    ${this.dateFilterComponent('transactions')}
                    <div class="card p-6 rounded-lg"><div id="transactions-table-container" class="overflow-x-auto"><table class="table-custom w-full text-sm"><thead><tr><th>Status</th><th>Valor</th><th>Origem</th><th>Provedor PIX</th><th>Data</th></tr></thead><tbody id="transactions-table-body"><tr><td colspan="5" class="text-center text-gray-500">Carregando transações...</td></tr></tbody></table></div></div>
                </div>`;
            },
            settings() {
                const { settings } = App.state.data;
                const providers = [
                    { value: 'pushinpay', text: 'PushinPay' },
                    { value: 'cnpay', text: 'CN Pay' },
                    { value: 'oasyfy', text: 'Oasy.fy' }
                ];
                const createSelect = (name, selectedValue) => {
                    const options = providers.map(p => `<option value="${p.value}" ${p.value === selectedValue ? 'selected' : ''}>${p.text}</option>`).join('');
                    return `<select name="${name}" class="form-select w-full p-2 rounded-md">${options}<option value="" ${!selectedValue ? 'selected' : ''}>Nenhum</option></select>`;
                };
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Configurações de PIX</h1>
                    <form id="pixSettingsForm" class="max-w-4xl">
                        <div class="flex border-b border-slate-700 mb-6" id="pix-settings-tabs">
                            <button type="button" data-tab="priority" class="tab-button active">Ordem de Prioridade</button>
                            <button type="button" data-tab="credentials" class="tab-button ml-2">Credenciais</button>
                        </div>

                        <div id="tab-priority" class="tab-content active space-y-8">
                            <div class="card p-6 rounded-lg">
                                <h2 class="text-xl font-semibold mb-2 text-white">Ordem de Prioridade dos Provedores</h2>
                                <p class="text-sm text-gray-400 mb-4">Defina a ordem em que o sistema tentará gerar o PIX. Se o Provedor Primário falhar, o sistema automaticamente tentará o próximo na lista.</p>
                                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <div>
                                        <label class="block mb-2 text-sm font-medium text-gray-400">1º - Provedor Primário</label>
                                        ${createSelect('pix_provider_primary', settings.pix_provider_primary)}
                                    </div>
                                    <div>
                                        <label class="block mb-2 text-sm font-medium text-gray-400">2º - Provedor Secundário</label>
                                        ${createSelect('pix_provider_secondary', settings.pix_provider_secondary)}
                                    </div>
                                    <div>
                                        <label class="block mb-2 text-sm font-medium text-gray-400">3º - Provedor Terciário</label>
                                        ${createSelect('pix_provider_tertiary', settings.pix_provider_tertiary)}
                                    </div>
                                </div>
                                <div class="mt-6 pt-6 border-t border-slate-700">
                                     <button type="button" id="testPriorityRouteBtn" class="btn btn-green w-full md:w-auto">Testar Rota de Prioridade</button>
                                </div>
                            </div>
                        </div>

                        <div id="tab-credentials" class="tab-content space-y-6">
                            <div class="card p-6 rounded-lg">
                                <div class="flex justify-between items-start mb-4">
                                    <div>
                                        <h3 class="text-lg font-medium text-sky-400 inline-block">PushinPay</h3>
                                        <span id="status-indicator-pushinpay"></span>
                                    </div>
                                    <button type="button" data-provider="pushinpay" class="test-pix-btn btn btn-secondary text-xs py-1 px-3">Testar Conexão</button>
                                </div>
                                <label class="block mb-2 text-sm text-gray-400">Bearer Token</label>
                                <input name="pushinpay_token" type="password" value="${settings.pushinpay_token || ''}" class="form-input w-full p-2 rounded-md">
                            </div>

                            <div class="card p-6 rounded-lg">
                                <div class="flex justify-between items-start mb-4">
                                    <div>
                                        <h3 class="text-lg font-medium text-sky-400 inline-block">CN Pay</h3>
                                        <span id="status-indicator-cnpay"></span>
                                    </div>
                                    <button type="button" data-provider="cnpay" class="test-pix-btn btn btn-secondary text-xs py-1 px-3">Testar Conexão</button>
                                </div>
                                <label class="block mb-2 text-sm text-gray-400">Chave Pública (public-key)</label>
                                <input name="cnpay_public_key" type="password" value="${settings.cnpay_public_key || ''}" class="form-input w-full p-2 rounded-md">
                                <label class="block mt-4 mb-2 text-sm text-gray-400">Chave Privada (secret-key)</label>
                                <input name="cnpay_secret_key" type="password" value="${settings.cnpay_secret_key || ''}" class="form-input w-full p-2 rounded-md">
                            </div>
                            
                            <div class="card p-6 rounded-lg">
                                 <div class="flex justify-between items-start mb-4">
                                    <div>
                                        <h3 class="text-lg font-medium text-sky-400 inline-block">Oasy.fy</h3>
                                        <span id="status-indicator-oasyfy"></span>
                                    </div>
                                    <button type="button" data-provider="oasyfy" class="test-pix-btn btn btn-secondary text-xs py-1 px-3">Testar Conexão</button>
                                </div>
                                <label class="block mb-2 text-sm text-gray-400">Chave Pública (public-key)</label>
                                <input name="oasyfy_public_key" type="password" value="${settings.oasyfy_public_key || ''}" class="form-input w-full p-2 rounded-md">
                                <label class="block mt-4 mb-2 text-sm text-gray-400">Chave Privada (secret-key)</label>
                                <input name="oasyfy_secret_key" type="password" value="${settings.oasyfy_secret_key || ''}" class="form-input w-full p-2 rounded-md">
                            </div>
                        </div>
                        
                        <div class="mt-8"><button type="submit" class="btn w-full p-3 font-bold rounded-md">Salvar Configurações</button></div>
                    </form>
                </div>`;
            },
            integrations() {
                const { settings } = App.state.data;
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Integrações</h1>
                    <div class="max-w-2xl">
                        <form id="utmifySettingsForm" class="space-y-8">
                             <div class="card p-6 rounded-lg">
                                <h2 class="text-xl font-semibold text-white">Utmify</h2>
                                <p class="text-sm text-gray-400 mt-1 mb-4">Integre com a Utmify para espelhar suas vendas e analisar a performance por UTMs.</p>
                                <label class="block mb-2 text-sm text-gray-400">Token da API Utmify (x-api-token)</label>
                                <input name="utmify_api_token" type="password" value="${settings.utmify_api_token || ''}" class="form-input w-full p-2 rounded-md">
                            </div>
                            <div><button type="submit" class="btn w-full p-3 font-bold rounded-md">Salvar Integrações</button></div>
                        </form>
                    </div>
                </div>`;
            },
            documentation() {
                return `
                <div class="animate-fade-in">
                    <h1 class="text-3xl font-bold text-white mb-6">Documentação e Chave de API</h1>
                    <div class="grid grid-cols-1 gap-8 max-w-2xl">
                        <div class="card p-6 rounded-lg">
                            <h2 class="text-xl font-semibold mb-4 text-white">Sua Chave de API HotTrack</h2>
                            <p class="text-sm text-gray-400 mb-4">Use esta chave para autenticar suas requisições na API HotTrack (ex: gerar PIX, consultar status).</p>
                            <div class="flex items-center gap-2">
                                <input id="hottrack-api-key" type="password" readonly value="${App.state.data.settings.api_key || ''}" class="form-input flex-grow p-2 rounded-md">
                                <button type="button" class="toggle-visibility-btn p-2 text-gray-400 hover:text-white" data-target="#hottrack-api-key"><svg class="pointer-events-none h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg></button>
                                <button type="button" class="copy-btn btn text-sm py-2 px-3" data-target="#hottrack-api-key">Copiar</button>
                            </div>
                        </div>
                        <div class="card p-8 rounded-lg">
                            <h2 class="text-xl font-semibold mb-4 text-white">Documentação Completa</h2>
                            <p class="text-gray-400 mb-4">Acesse nosso guia detalhado com o passo a passo completo para integrar o HotTrack com o ManyChat e outras ferramentas.</p>
                            <a href="https://documentacaohot.netlify.app/" target="_blank" rel="noopener noreferrer" class="btn inline-flex items-center gap-2">Acessar Documentação<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg></a>
                        </div>
                    </div>
                </div>`;
            },
            modal(title, content) {
                return `<div id="modal" class="modal active"><div class="card p-6 rounded-lg w-full max-w-lg animate-fade-in"><div class="flex justify-between items-center mb-4"><h2 class="text-xl font-bold text-white">${title}</h2><button id="closeModalBtn" class="text-gray-400 hover:text-white text-2xl">&times;</button></div>${content}</div></div>`;
            }
        },

        addAuthEventListeners() {
            const container = document.getElementById('app');
            container.addEventListener('click', (e) => {
                if (e.target.id === 'showRegister') { e.preventDefault(); this.renderLogin('register'); }
                if (e.target.id === 'showLogin') { e.preventDefault(); this.renderLogin('login'); }
            });
            container.addEventListener('submit', async (e) => {
                const form = e.target;
                if(form.id === 'loginForm' || form.id === 'registerForm') {
                    e.preventDefault();
                    const data = Object.fromEntries(new FormData(form).entries());
                    if (form.id === 'loginForm') await this.login(data.email, data.password);
                    if (form.id === 'registerForm') await this.register(data.name, data.email, data.password);
                }
            });
        },
        
        addDashboardEventListeners() {
            document.addEventListener('click', async (e) => {
                if (e.target.id === 'logoutButton') this.logout();
                if (e.target.closest('#closeModalBtn')) document.getElementById('modal-container').innerHTML = '';
                
                const sidebarLink = e.target.closest('.nav-link');
                if (sidebarLink) this.navigateTo(sidebarLink.dataset.target);

                const copyBtn = e.target.closest('.copy-btn');
                if (copyBtn) {
                    const targetInput = document.querySelector(copyBtn.dataset.target);
                    if(targetInput) {
                        const textToCopy = targetInput.value || targetInput.textContent;
                        navigator.clipboard.writeText(textToCopy).then(() => {
                            const originalText = copyBtn.textContent;
                            copyBtn.textContent = 'Copiado!';
                            setTimeout(() => { copyBtn.textContent = originalText; }, 2000);
                        });
                    }
                }
                
                const toggleBtn = e.target.closest('.toggle-visibility-btn');
                if (toggleBtn) {
                    const targetInput = document.querySelector(toggleBtn.dataset.target);
                    const isPassword = targetInput.type === 'password';
                    targetInput.type = isPassword ? 'text' : 'password';
                    toggleBtn.innerHTML = isPassword 
                        ? `<svg class="pointer-events-none h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.243 4.243L6.228 6.228" /></svg>` 
                        : `<svg class="pointer-events-none h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>`;
                }

                if (e.target.classList.contains('generate-pressel-code-btn')) {
                    const presselId = e.target.dataset.id;
                    const pressel = this.state.data.pressels.find(p => p.id == presselId);
                    if (pressel) this.generatePresselCode(pressel);
                }

                if (e.target.classList.contains('generate-checkout-code-btn')) {
                    const checkoutId = e.target.dataset.id;
                    this.generateCheckoutHTML(checkoutId);
                }
                
                if (e.target.classList.contains('test-bot-btn')) {
                    const botId = e.target.dataset.id;
                    this.testBotConnection(botId, e.target);
                }

                if (e.target.classList.contains('test-pix-btn')) {
                    const provider = e.target.dataset.provider;
                    this.testIndividualPixConnection(provider, e.target);
                }
                
                if (e.target.id === 'testPriorityRouteBtn') {
                    this.testPriorityRoute(e.target);
                }

                const tabButton = e.target.closest('.tab-button');
                if (tabButton) {
                    const tabName = tabButton.dataset.tab;
                    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                    tabButton.classList.add('active');
                    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                    document.getElementById(`tab-${tabName}`).classList.add('active');
                }

                if (e.target.classList.contains('delete-pixel-btn') || e.target.classList.contains('delete-bot-btn') || e.target.classList.contains('delete-pressel-btn') || e.target.classList.contains('delete-checkout-btn')) {
                    const id = e.target.dataset.id;
                    let type = '', endpoint = '';
                    if (e.target.classList.contains('delete-pixel-btn')) { type = 'pixels'; endpoint = 'pixels'; }
                    if (e.target.classList.contains('delete-bot-btn')) { type = 'bots'; endpoint = 'bots'; }
                    if (e.target.classList.contains('delete-pressel-btn')) { type = 'pressels'; endpoint = 'pressels'; }
                    if (e.target.classList.contains('delete-checkout-btn')) { type = 'checkouts'; endpoint = 'checkouts'; }

                    if (confirm(`Tem certeza que deseja excluir este item?`)) {
                        try {
                            await this.apiRequest(`/api/${endpoint}/${id}`, 'DELETE');
                            this.state.data[type] = this.state.data[type].filter(item => item.id != id);
                            this.navigateTo(this.state.currentPage);
                            this.showToast('Item excluído com sucesso!', 'success');
                        } catch(err) {}
                    }
                }
                
                const filterContainer = e.target.closest('#transactions-date-filter, #dashboard-date-filter');
                if (filterContainer) {
                    const page = filterContainer.id.split('-')[0];
                    if (e.target.dataset.period) { this.handleFilterChange(page, e.target.dataset.period); }
                    else if (e.target.id === `apply-custom-date-filter-${page}`) {
                        const startDate = document.getElementById(`${page}-start-date`).value;
                        const endDate = document.getElementById(`${page}-end-date`).value;
                        if (startDate && endDate) { this.handleFilterChange(page, 'custom', startDate, endDate); }
                        else { this.showToast('Por favor, selecione data de início e fim.', 'error'); }
                    } else if (e.target.id === `clear-date-filter-${page}`) { this.handleFilterChange(page, 'all'); }
                }
            });

            document.addEventListener('submit', async (e) => {
                const form = e.target.closest('form');
                if (!form || form.id === 'loginForm' || form.id === 'registerForm') return;
                
                e.preventDefault();
                const button = form.querySelector('button[type="submit"]');
                const originalButtonText = button.innerHTML;
                button.innerHTML = 'Salvando...';
                button.disabled = true;

                let data = Object.fromEntries(new FormData(form).entries());
                try {
                    if (form.id === 'pixSettingsForm') {
                        await this.apiRequest('/api/settings/pix', 'POST', data);
                        App.state.data.settings = { ...App.state.data.settings, ...data };
                        this.showToast('Configurações PIX salvas!', 'success');
                    }
                    else if (form.id === 'utmifySettingsForm') {
                        await this.apiRequest('/api/settings/utmify', 'POST', data);
                        App.state.data.settings = { ...App.state.data.settings, ...data };
                        this.showToast('Integração Utmify salva!', 'success');
                    }
                    else if (form.id === 'pixelForm') {
                        const newPixel = await this.apiRequest('/api/pixels', 'POST', data);
                        if (newPixel) { this.state.data.pixels.unshift(newPixel); this.navigateTo('pixels'); }
                    }
                    else if (form.id === 'botForm') {
                        const newBot = await this.apiRequest('/api/bots', 'POST', data);
                        if (newBot) { this.state.data.bots.unshift(newBot); this.navigateTo('bots'); }
                    }
                    else if (form.id === 'presselForm') {
                        const pixel_ids = Array.from(form.querySelectorAll('input[name="pixel_ids"]:checked')).map(cb => cb.value);
                        if (pixel_ids.length === 0) {
                             this.showToast('Selecione ao menos um pixel.', 'error');
                        } else {
                            const payload = { ...data, pixel_ids };
                            const newPressel = await this.apiRequest('/api/pressels', 'POST', payload);
                            if (newPressel) {
                                this.state.data.pressels.unshift(newPressel);
                                this.navigateTo('pressels');
                                this.generatePresselCode(newPressel);
                            }
                        }
                    }
                    else if (form.id === 'checkoutForm') {
                        const pixel_ids = Array.from(form.querySelectorAll('input[name="pixel_ids"]:checked')).map(cb => cb.value);
                        if (pixel_ids.length === 0) {
                             this.showToast('Selecione ao menos um pixel para o checkout.', 'error');
                        } else {
                            const payload = { ...data, pixel_ids };
                            const newCheckout = await this.apiRequest('/api/checkouts', 'POST', payload);
                            if (newCheckout) {
                                this.state.data.checkouts.unshift(newCheckout);
                                this.navigateTo('checkouts');
                                this.generateCheckoutHTML(newCheckout.id);
                            }
                        }
                    }
                    else if (form.id === 'broadcastForm') {
                        const botId = data.botId;
                        let messageText = data.messageText;
                        const checkoutShortcodes = messageText.match(/\[([a-zA-Z0-9_-]+)\]/g) || [];
                        
                        if(checkoutShortcodes) {
                            for(const shortcode of checkoutShortcodes) {
                                const checkoutName = shortcode.slice(1, -1);
                                const checkout = this.state.data.checkouts.find(c => c.name.toLowerCase() === checkoutName.toLowerCase());
                                if(checkout) {
                                    let checkoutUrl = `https://hottracker.netlify.app/checkout.html?checkoutId=${checkout.id}&apiKey=${this.state.data.settings.api_key}`;
                                    if(checkout.value_type === 'fixed') {
                                        checkoutUrl += `&value=${checkout.fixed_value_cents}`;
                                    }
                                    messageText = messageText.replace(shortcode, `[${checkout.product_name}](${checkoutUrl})`);
                                } else {
                                    this.showToast(`Checkout com o nome "${checkoutName}" não encontrado.`, 'error');
                                    throw new Error("Checkout not found");
                                }
                            }
                        }

                        const payload = { botId, messageText };
                        await this.apiRequest('/api/broadcasts', 'POST', payload);
                        await this.loadBroadcastHistory(botId);
                    }
                } catch(e) { /* Erros são tratados por apiRequest ou lógica customizada */ }
                finally {
                    if(button) {
                        button.innerHTML = originalButtonText;
                        button.disabled = false;
                    }
                }
            });
            
            document.addEventListener('change', async e => {
                if (e.target.id === 'value-type-selector') {
                    const container = document.getElementById('fixed-value-container');
                    if (container) {
                        container.style.display = e.target.value === 'fixed' ? 'block' : 'none';
                    }
                }
                if (e.target.id === 'broadcast-bot-selector') {
                    const botId = e.target.value;
                    if (botId) await App.loadBroadcastHistory(botId);
                }
            });
        },

        async apiRequest(endpoint, method = 'GET', body = null) {
            try {
                const headers = { 'Content-Type': 'application/json' };
                if (this.state.token) {
                    headers['Authorization'] = `Bearer ${this.state.token}`;
                }
                const options = { method, headers };
                if (body) {
                    options.body = JSON.stringify(body);
                }
        
                const response = await fetch(`${this.state.API_BASE_URL}${endpoint}`, options);
        
                if (response.status === 304) {
                    return this.state.data; 
                }
                if (response.status === 204) {
                    return null;
                }
        
                const data = await response.json();
        
                if (!response.ok) {
                    throw data;
                }
                return data;
            } catch (error) {
                if (!(error instanceof SyntaxError)) {
                    this.showToast(error.message || 'Falha na conexão', 'error');
                }
                if (error.message && (error.message.includes('inválido') || error.message.includes('expirado'))) {
                    this.logout();
                }
                throw error;
            }
        },
        
        async login(email, password) {
            try {
                const data = await this.apiRequest('/api/sellers/login', 'POST', { email, password });
                if (data && data.token) {
                    localStorage.setItem('hottrack_token', data.token);
                    await this.init();
                } else {
                    this.showToast('Resposta de login inválida recebida do servidor.', 'error');
                }
            } catch (e) {
                // O erro já é tratado e exibido pela função apiRequest
            }
        },
        
        async register(name, email, password) {
            try {
                await this.apiRequest('/api/sellers/register', 'POST', { name, email, password });
                this.showToast('Cadastro realizado! Faça o login.', 'success');
                this.renderLogin('login');
            } catch (e) {}
        },

        logout() {
            localStorage.removeItem('hottrack_token');
            this.state.token = null;
            this.renderLogin();
        },

        navigateTo(page) {
            this.state.currentPage = page;
            const contentContainer = document.getElementById('content');
            if (contentContainer && this.templates[page]) {
                contentContainer.innerHTML = this.templates[page]();
                
                document.querySelectorAll('.nav-link').forEach(item => { item.classList.toggle('active', item.dataset.target === page); });
                
                if (page === 'dashboard') this.handleFilterChange(page, 'last7days');
                else if (page === 'transactions') this.fetchTransactions();
                else if (page === 'settings') this.updateAllPixStatusIndicators();
                else if (page === 'bots') this.updateAllBotStatusIndicators();
            }
        },
        
        async fetchDashboardMetrics() {
            try {
                const { startDate, endDate } = this.state.dateFilter;
                const query = new URLSearchParams({ 
                    startDate: startDate || '',
                    endDate: endDate || ''
                }).toString();
                
                const metrics = await this.apiRequest(`/api/dashboard/metrics?${query}`);
                this.state.data.dashboard = metrics;

                document.getElementById('metric-clicks').textContent = metrics.total_clicks || '0';
                document.getElementById('metric-generated').textContent = metrics.total_pix_generated || '0';
                document.getElementById('metric-paid').textContent = metrics.total_pix_paid || '0';
                document.getElementById('metric-total-revenue').textContent = `R$ ${(metrics.total_revenue || 0).toFixed(2).replace('.', ',')}`;
                document.getElementById('metric-paid-revenue').textContent = `R$ ${(metrics.paid_revenue || 0).toFixed(2).replace('.', ',')}`;
                
                const botsTableBody = document.getElementById('bots-performance-table');
                if (metrics.bots_performance && metrics.bots_performance.length > 0) {
                    botsTableBody.innerHTML = metrics.bots_performance.map(b => `<tr class="hover:bg-slate-800/50"><td>${b.bot_name}</td><td>${b.total_clicks || '0'}</td><td>${b.total_pix_paid || '0'}</td><td>R$ ${(b.paid_revenue || 0).toFixed(2).replace('.', ',')}</td></tr>`).join('');
                } else {
                    botsTableBody.innerHTML = '<tr><td colspan="4" class="text-center text-gray-500">Nenhum dado de bot.</td></tr>';
                }
                const trafficTableBody = document.getElementById('traffic-by-state-table');
                if (metrics.clicks_by_state && metrics.clicks_by_state.length > 0) {
                    trafficTableBody.innerHTML = metrics.clicks_by_state.map(s => `<tr class="hover:bg-slate-800/50"><td>${s.state}</td><td>${s.total_clicks}</td></tr>`).join('');
                } else {
                    trafficTableBody.innerHTML = '<tr><td colspan="2" class="text-center text-gray-500">Nenhum tráfego registrado por estado.</td></tr>';
                }
                
                this.renderRevenueChart();

            } catch (e) { console.error("Erro ao carregar métricas do painel:", e); }
        },
        async fetchTransactions() {
            const tableBody = document.getElementById('transactions-table-body');
            tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-gray-500">Carregando transações...</td></tr>';
            try {
                const transactions = await this.apiRequest('/api/transactions');
                this.state.data.transactions = transactions;
                this.renderTransactionsTable();
            } catch (e) {
                tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-red-400">Erro ao carregar transações.</td></tr>';
            }
        },
        renderTransactionsTable() {
            const tableBody = document.getElementById('transactions-table-body');
            if (!tableBody) return;

            const { period, startDate, endDate } = this.state.dateFilter;
            let filteredTransactions = this.state.data.transactions;

            if (period !== 'all' && startDate && endDate) {
                const start = new Date(`${startDate}T00:00:00`);
                const end = new Date(`${endDate}T23:59:59`);
                filteredTransactions = this.state.data.transactions.filter(t => {
                    const transactionDate = new Date(t.created_at);
                    return transactionDate >= start && transactionDate <= end;
                });
            }

            if (filteredTransactions.length > 0) {
                tableBody.innerHTML = filteredTransactions.map(t => {
                    const statusColor = t.status === 'paid' ? 'text-green-400' : 'text-yellow-400';
                    const statusText = t.status === 'paid' ? 'Pago' : 'Pendente';
                    const formattedValue = `R$ ${parseFloat(t.pix_value).toFixed(2).replace('.', ',')}`;
                    const formattedDate = new Date(t.created_at).toLocaleString('pt-BR');
                    return `<tr class="hover:bg-slate-800/50"><td class="${statusColor}">${statusText}</td><td>${formattedValue}</td><td>${t.source_name || 'Checkout'}</td><td>${t.provider.toUpperCase()}</td><td>${formattedDate}</td></tr>`;
                }).join('');
            } else {
                tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-gray-500">Nenhuma transação encontrada.</td></tr>';
            }
        },
        handleFilterChange(page, period, customStartDate, customEndDate) {
            const now = new Date();
            let startDate, endDate;

            switch(period) {
                case 'today': startDate = endDate = now.toISOString().split('T')[0]; break;
                case 'yesterday':
                    const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1);
                    startDate = endDate = yesterday.toISOString().split('T')[0]; break;
                case 'last7days':
                    endDate = now.toISOString().split('T')[0];
                    const sevenDaysAgo = new Date(now); sevenDaysAgo.setDate(now.getDate() - 6);
                    startDate = sevenDaysAgo.toISOString().split('T')[0]; break;
                case 'thisMonth':
                    startDate = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
                    endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0]; break;
                case 'custom': startDate = customStartDate; endDate = customEndDate; break;
                case 'all': default: startDate = null; endDate = null;
            }

            this.state.dateFilter = { period, startDate, endDate };

            const filterContainer = document.getElementById(`${page}-date-filter`);
            if (filterContainer) {
                filterContainer.outerHTML = this.templates.dateFilterComponent(page);
            }
            
            if (page === 'dashboard') this.fetchDashboardMetrics();
            else if (page === 'transactions') this.renderTransactionsTable();
        },
        
        renderRevenueChart() {
            const ctx = document.getElementById('revenueChart');
            if (!ctx) return;
            
            const data = this.state.data.dashboard.daily_revenue || [];
            const labels = data.map(item => new Date(item.date).toLocaleDateString('pt-BR', { timeZone: 'UTC' }));
            const revenues = data.map(item => item.revenue);

            if (this.state.revenueChart) this.state.revenueChart.destroy();

            this.state.revenueChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Faturamento Pago', data: revenues, backgroundColor: 'rgba(56, 189, 248, 0.2)',
                        borderColor: '#38bdf8', borderWidth: 2, tension: 0.4, fill: true,
                        pointBackgroundColor: '#38bdf8', pointRadius: 4, pointHoverRadius: 6,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: true,
                    scales: {
                        y: { beginAtZero: true, ticks: { color: '#94a3b8', callback: (value) => 'R$ ' + value.toFixed(2).replace('.', ',') }, grid: { color: 'rgba(51, 65, 85, 0.5)' } },
                        x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(51, 65, 85, 0.5)' } }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#020617', titleColor: '#e2e8f0', bodyColor: '#cbd5e1',
                            borderColor: '#334155', borderWidth: 1,
                            callbacks: { label: (context) => `Faturamento: R$ ${context.raw.toFixed(2).replace('.', ',')}` }
                        }
                    }
                }
            });
        },
        
        generatePresselCode(pressel) {
            const { settings } = this.state.data;
            const botLink = `https://t.me/${pressel.bot_name}?start=`;
            const sellerApiKey = settings.api_key;
            const apiBaseUrl = this.state.API_BASE_URL;

            const htmlContent = `<!DOCTYPE html><html><head><title>Redirecionando...</title><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('track', 'PageView');fbq('track', 'ViewContent');<\/script></head><body><p>Aguarde um instante...</p><script>const config = { API_BASE_URL: '${apiBaseUrl}', sellerApiKey: '${sellerApiKey}', presselId: ${pressel.id}, whitePageUrl: '${pressel.white_page_url}', botLink: '${botLink}' };async function registerClickAndRedirect() { try { const urlParams = new URLSearchParams(window.location.search); const bodyPayload = { sellerApiKey: config.sellerApiKey, presselId: config.presselId, referer: document.referrer, user_agent: navigator.userAgent, fbclid: urlParams.get('fbclid'), fbp: document.cookie.split('; ').find(row => row.startsWith('_fbp='))?.split('=')[1], fbc: document.cookie.split('; ').find(row => row.startsWith('_fbc='))?.split('=')[1], utm_source: urlParams.get('utm_source'), utm_campaign: urlParams.get('utm_campaign'), utm_medium: urlParams.get('utm_medium'), utm_content: urlParams.get('utm_content'), utm_term: urlParams.get('utm_term')}; Object.keys(bodyPayload).forEach(key => (bodyPayload[key] === null || bodyPayload[key] === undefined) && delete bodyPayload[key]); const response = await fetch(config.API_BASE_URL + '/api/registerClick', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bodyPayload) }); if (!response.ok) throw new Error('Failed to register click'); const data = await response.json(); window.location.href = config.botLink + data.click_id; } catch (error) { console.error('Redirect Error:', error); window.location.href = config.whitePageUrl; } } registerClickAndRedirect();<\/script></body></html>`;

            const modalContent = `<p class="text-sm text-gray-400 mb-4">Copie e cole este código no HTML da sua página. Lembre-se de adicionar os IDs dos seus pixels no local indicado.</p><textarea id="pressel-code-textarea" class="form-input w-full p-2 rounded-md font-mono text-xs" rows="12" readonly>${htmlContent}</textarea><button class="copy-btn btn w-full mt-4 py-2" data-target="#pressel-code-textarea">Copiar Código</button>`;
            
            document.getElementById('modal-container').innerHTML = this.templates.modal(`Código da Pressel: ${pressel.name}`, modalContent);
        },

        generateCheckoutHTML(checkoutId) {
            const checkout = this.state.data.checkouts.find(c => c.id == checkoutId);
            const { settings, pixels } = this.state.data;
            if (!checkout) {
                this.showToast('Checkout não encontrado.', 'error');
                return;
            }

            const selectedPixels = pixels.filter(p => checkout.pixel_ids.includes(p.id));
            const fbqInitBlock = selectedPixels.map(p => `fbq('init', '${p.pixel_id}');`).join('\\n        ');

            const htmlTemplate = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pagamento Seguro</title>
    <style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');:root{--primary-color:#2c5282;--secondary-color:#e2e8f0;--success-color:#38a169;--text-color:#2d3748;--light-text-color:#718096;--background-color:#f7fafc}body{font-family:'Inter',sans-serif;background-color:var(--background-color);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh;color:var(--text-color)}.container{background-color:#fff;padding:2rem;border-radius:12px;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -2px rgba(0,0,0,.05);width:100%;max-width:420px;text-align:center;box-sizing:border-box;margin:1rem}.header h1{font-size:1.5rem;margin-bottom:.5rem}.header p{color:var(--light-text-color);margin-top:0}.timer{background-color:var(--secondary-color);color:var(--primary-color);font-weight:600;padding:.5rem 1rem;border-radius:8px;display:inline-block;margin-bottom:1.5rem}#qr-code-container{position:relative;margin:1rem 0;min-height:280px;display:flex;justify-content:center;align-items:center}#qr-code-img{border:6px solid var(--secondary-color);border-radius:8px;max-width:100%;height:auto;display:none}.loader{border:5px solid #f3f3f3;border-top:5px solid var(--primary-color);border-radius:50%;width:50px;height:50px;animation:spin 1s linear infinite}@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}.copy-button{background-color:var(--primary-color);color:#fff;border:none;padding:.8rem 1.5rem;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:background-color .3s,transform .2s;width:100%;margin-top:1rem}.copy-button:hover{background-color:#3182ce}.copy-button:active{transform:scale(.98)}#copy-feedback{color:var(--success-color);font-weight:600;margin-top:.5rem;height:20px;visibility:hidden;opacity:0;transition:visibility 0s,opacity .5s linear}#copy-feedback.visible{visibility:visible;opacity:1}.instructions{margin-top:1.5rem;color:var(--light-text-color);font-size:.9rem}.footer{margin-top:2rem;font-size:.8rem;color:#a0aec0}.footer svg{vertical-align:middle;width:16px;height:16px;margin-right:5px}</style>
    <script>
        !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
        ${fbqInitBlock}
        fbq('track', 'PageView');
    <\/script>
</head>
<body>
    <div class="container"><div class="header"><h1 id="product-name">Finalize seu Pagamento</h1><p>Escaneie o QR Code ou copie o código abaixo.</p></div><div class="timer">Expira em: <span id="countdown">10:00</span></div><div id="qr-code-container"><div id="loader" class="loader"></div><img id="qr-code-img" src="" alt="PIX QR Code"></div><button class="copy-button" id="copy-btn" disabled><span id="btn-text">Carregando PIX...</span></button><div id="copy-feedback">Código PIX copiado!</div><div class="instructions">1. Abra o app do seu banco.<br>2. Escolha a opção Pagar com PIX.<br>3. Escaneie o QR Code ou use o "Copia e Cola".</div><div class="footer"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clip-rule="evenodd" /></svg> Pagamento seguro</div></div>
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const CONFIG = { API_BASE_URL: '${this.state.API_BASE_URL}', SELLER_API_KEY: '${settings.api_key}', CHECKOUT_ID: ${checkout.id}, PRODUCT_NAME: '${checkout.product_name}', REDIRECT_URL: '${checkout.redirect_url}', VALUE_TYPE: '${checkout.value_type}', FIXED_VALUE_CENTS: ${checkout.fixed_value_cents || null}, POLLING_INTERVAL: 5000, TIMER_DURATION_MINUTES: 10 };
        const qrCodeImg = document.getElementById('qr-code-img'), loader = document.getElementById('loader'), copyBtn = document.getElementById('copy-btn'), btnText = document.getElementById('btn-text'), copyFeedback = document.getElementById('copy-feedback'), countdownEl = document.getElementById('countdown');
        let pixCode = '', transactionId = '', statusCheckInterval;
        function displayError(message) { console.error(message); loader.style.display = 'none'; qrCodeImg.style.display = 'none'; document.querySelector('.header h1').textContent = 'Ocorreu um Erro'; document.querySelector('.header p').textContent = message; copyBtn.disabled = true; btnText.textContent = 'Erro ao Gerar PIX'; }
        function startTimer() { let time = CONFIG.TIMER_DURATION_MINUTES * 60; const timerInterval = setInterval(() => { if (time <= 0) { clearInterval(timerInterval); countdownEl.textContent = 'Expirado'; displayError('O tempo para pagamento expirou.'); return; } time--; const minutes = Math.floor(time / 60).toString().padStart(2, '0'); const seconds = (time % 60).toString().padStart(2, '0'); countdownEl.textContent = \`\${minutes}:\${seconds}\`; }, 1000); }
        async function copyPixCode() { try { await navigator.clipboard.writeText(pixCode); copyFeedback.classList.add('visible'); setTimeout(() => copyFeedback.classList.remove('visible'), 2000); } catch (err) { console.error('Falha ao copiar:', err); } }
        async function checkPaymentStatus() { if (!transactionId) return; try { const response = await fetch(\`\${CONFIG.API_BASE_URL}/api/pix/status/\${transactionId}\`, { headers: { 'x-api-key': CONFIG.SELLER_API_KEY } }); if (!response.ok) return; const data = await response.json(); if (data.status === 'paid' || data.status === 'COMPLETED') { clearInterval(statusCheckInterval); window.location.href = CONFIG.REDIRECT_URL; } } catch (error) { console.error('Erro ao verificar status:', error); } }
        async function generatePix(click_id, value_cents) { try { const response = await fetch(\`\${CONFIG.API_BASE_URL}/api/pix/generate\`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': CONFIG.SELLER_API_KEY }, body: JSON.stringify({ value_cents, click_id }) }); if (!response.ok) { const errorData = await response.json(); throw new Error(errorData.message || 'Erro do servidor'); } const data = await response.json(); pixCode = data.qr_code_text; transactionId = data.transaction_id; qrCodeImg.src = data.qr_code_base64; loader.style.display = 'none'; qrCodeImg.style.display = 'block'; copyBtn.disabled = false; btnText.textContent = 'Copiar Código PIX'; startTimer(); statusCheckInterval = setInterval(checkPaymentStatus, CONFIG.POLLING_INTERVAL); checkPaymentStatus(); } catch (error) { displayError(error.message || 'Não foi possível gerar o PIX.'); } }
        async function initializeCheckout() { try { document.getElementById('product-name').textContent = CONFIG.PRODUCT_NAME; let final_value_cents; if (CONFIG.VALUE_TYPE === 'fixed') { final_value_cents = CONFIG.FIXED_VALUE_CENTS; if (!final_value_cents) return displayError('Valor do produto não configurado.'); } else { const urlValue = new URLSearchParams(window.location.search).get('value'); if (!urlValue) return displayError('Valor não fornecido na URL (ex: ?value=1990).'); final_value_cents = parseInt(urlValue, 10); } const urlParams = new URLSearchParams(window.location.search); const bodyPayload = { sellerApiKey: CONFIG.SELLER_API_KEY, checkoutId: CONFIG.CHECKOUT_ID, referer: document.referrer, user_agent: navigator.userAgent, fbclid: urlParams.get('fbclid'), fbp: document.cookie.split('; ').find(row => row.startsWith('_fbp='))?.split('=')[1], fbc: document.cookie.split('; ').find(row => row.startsWith('_fbc='))?.split('=')[1], utm_source: urlParams.get('utm_source'), utm_campaign: urlParams.get('utm_campaign'), utm_medium: urlParams.get('utm_medium'), utm_content: urlParams.get('utm_content'), utm_term: urlParams.get('utm_term') }; Object.keys(bodyPayload).forEach(key => (bodyPayload[key] === null || bodyPayload[key] === undefined) && delete bodyPayload[key]); const clickResponse = await fetch(CONFIG.API_BASE_URL + '/api/registerClick', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bodyPayload) }); if (!clickResponse.ok) throw new Error('Falha ao rastrear o acesso.'); const clickData = await clickResponse.json(); await generatePix(clickData.click_id, final_value_cents); } catch (error) { displayError(error.message); } }
        copyBtn.addEventListener('click', copyPixCode); initializeCheckout();
    });
    <\/script>
</body>
</html>`;

            const modalContent = `
                <p class="text-sm text-gray-400 mb-4">Copie o código abaixo, salve como 'index.html' e hospede no seu domínio.</p>
                <textarea id="checkout-code-textarea" class="form-input w-full p-2 rounded-md font-mono text-xs" rows="15" readonly></textarea>
                <button class="copy-btn btn w-full mt-4 py-2" data-target="#checkout-code-textarea">Copiar Código HTML</button>
            `;
            const modalContainer = document.getElementById('modal-container');
            modalContainer.innerHTML = this.templates.modal(`Código do Checkout: ${checkout.name}`, modalContent);
            modalContainer.querySelector('#checkout-code-textarea').value = htmlTemplate.trim();
        },

        async testIndividualPixConnection(provider, button) {
            const originalText = button.innerHTML;
            button.innerHTML = 'Testando...';
            button.disabled = true;
            this.updatePixStatusIndicator(provider, 'testing');
            
            const form = document.getElementById('pixSettingsForm');
            const formData = Object.fromEntries(new FormData(form).entries());
            try {
                await this.apiRequest('/api/settings/pix', 'POST', formData);
                App.state.data.settings = { ...App.state.data.settings, ...formData };
            } catch (e) {
                this.showToast('Erro ao salvar as configurações antes do teste.', 'error');
                button.innerHTML = originalText; button.disabled = false;
                this.updatePixStatusIndicator(provider); return;
            }

            try {
                const result = await this.apiRequest('/api/pix/test-provider', 'POST', { provider });
                localStorage.setItem(`pix_status_${provider}`, 'success');
                localStorage.setItem(`pix_timestamp_${provider}`, Date.now());
                
                const successModalContent = `<div class="space-y-4 text-sm"><div class="flex justify-between items-center"><span class="font-semibold text-gray-400">Provedor:</span> <span class="text-white">${result.provider}</span></div><div class="flex justify-between items-center"><span class="font-semibold text-gray-400">Adquirente:</span> <span class="text-white">${result.acquirer}</span></div><div class="flex justify-between items-center"><span class="font-semibold text-gray-400">Tempo de Resposta:</span> <span class="text-white">${result.responseTime}s</span></div><hr class="border-slate-700"><div><p class="font-semibold text-gray-400 mb-2">PIX Copia e Cola (R$ 0,05):</p><textarea id="pix-test-key" class="form-input w-full p-2 rounded-md font-mono text-xs" rows="4" readonly>${result.qr_code_text}</textarea><button class="copy-btn btn w-full mt-2 py-2 text-sm" data-target="#pix-test-key">Copiar Chave PIX</button></div></div>`;
                document.getElementById('modal-container').innerHTML = this.templates.modal('Conexão Bem-sucedida!', successModalContent);

            } catch (error) {
                localStorage.setItem(`pix_status_${provider}`, 'failure');
                localStorage.setItem(`pix_timestamp_${provider}`, Date.now());
                const errorModalContent = `<div class="text-center"><p class="text-lg font-medium text-red-400 mb-2">Falha na Conexão</p><p class="text-sm text-gray-400">${error.message || 'Ocorreu um erro desconhecido.'}</p></div>`;
                document.getElementById('modal-container').innerHTML = this.templates.modal('Erro no Teste', errorModalContent);
            } finally {
                button.innerHTML = originalText; button.disabled = false;
                this.updatePixStatusIndicator(provider);
            }
        },
        
        async testPriorityRoute(button) {
            const originalText = button.innerHTML;
            button.innerHTML = 'Testando Rota...';
            button.disabled = true;

            const form = document.getElementById('pixSettingsForm');
            const formData = Object.fromEntries(new FormData(form).entries());
            try {
                await this.apiRequest('/api/settings/pix', 'POST', formData);
                App.state.data.settings = { ...App.state.data.settings, ...formData };
            } catch (e) {
                this.showToast('Erro ao salvar as configurações antes do teste.', 'error');
                button.innerHTML = originalText; button.disabled = false; return;
            }

            try {
                const result = await this.apiRequest('/api/pix/test-priority-route', 'POST');
                const logHTML = result.log.map(line => `<li class="${line.startsWith('SUCESSO') ? 'text-green-400' : 'text-red-400'}">${line}</li>`).join('');
                const successModalContent = `<div class="space-y-4 text-sm"><div class="flex justify-between items-center"><span class="font-semibold text-gray-400">Provedor de Sucesso:</span> <span class="text-white">${result.provider} (${result.position})</span></div><div class="flex justify-between items-center"><span class="font-semibold text-gray-400">Tempo de Resposta:</span> <span class="text-white">${result.responseTime}s</span></div><hr class="border-slate-700"><div><p class="font-semibold text-gray-400 mb-2">Log de Tentativas:</p><ul class="text-xs font-mono list-disc list-inside space-y-1">${logHTML}</ul></div><hr class="border-slate-700"><div><p class="font-semibold text-gray-400 mb-2">PIX Copia e Cola (R$ 0,05):</p><textarea id="pix-test-key" class="form-input w-full p-2 rounded-md font-mono text-xs" rows="3" readonly>${result.qr_code_text}</textarea><button class="copy-btn btn w-full mt-2 py-2 text-sm" data-target="#pix-test-key">Copiar Chave PIX</button></div></div>`;
                document.getElementById('modal-container').innerHTML = this.templates.modal('Teste da Rota Concluído!', successModalContent);

            } catch (error) {
                const logHTML = error.log ? error.log.map(line => `<li class="text-red-400">${line}</li>`).join('') : '<li>Nenhum log disponível.</li>';
                const errorModalContent = `<div class="space-y-4 text-sm"><p class="text-lg font-medium text-red-400 text-center mb-2">Falha na Rota de Prioridade</p><p class="text-gray-400 text-center">${error.message}</p><hr class="border-slate-700"><div><p class="font-semibold text-gray-400 mb-2">Log de Tentativas:</p><ul class="text-xs font-mono list-disc list-inside space-y-1">${logHTML}</ul></div></div>`;
                document.getElementById('modal-container').innerHTML = this.templates.modal('Erro no Teste', errorModalContent);
            } finally {
                button.innerHTML = originalText; button.disabled = false;
            }
        },

        async testBotConnection(botId, button) {
            const originalText = button.innerHTML;
            button.innerHTML = '...';
            button.disabled = true;
            this.updateBotStatusIndicator(botId, 'testing');

            try {
                const result = await this.apiRequest('/api/bots/test-connection', 'POST', { bot_id: botId });
                localStorage.setItem(`bot_status_${botId}`, 'success');
                localStorage.setItem(`bot_timestamp_${botId}`, Date.now());
                this.showToast(result.message, 'success');
            } catch (error) {
                localStorage.setItem(`bot_status_${botId}`, 'failure');
                localStorage.setItem(`bot_timestamp_${botId}`, Date.now());
            } finally {
                button.innerHTML = originalText; button.disabled = false;
                this.updateBotStatusIndicator(botId);
            }
        },

        updateAllBotStatusIndicators() {
            if (this.state.data.bots && this.state.data.bots.length > 0) {
                this.state.data.bots.forEach(bot => this.updateBotStatusIndicator(bot.id));
            }
        },
        
        updateBotStatusIndicator(botId, mode) {
            const indicator = document.getElementById(`status-indicator-bot-${botId}`);
            if (!indicator) return;

            if (mode === 'testing') {
                indicator.textContent = 'Testando...';
                indicator.className = 'status-indicator testing';
                return;
            }

            const status = localStorage.getItem(`bot_status_${botId}`);
            const timestamp = localStorage.getItem(`bot_timestamp_${botId}`);

            if (status === 'success' && timestamp) {
                indicator.textContent = `Online (${this.formatTimeAgo(timestamp)})`;
                indicator.className = 'status-indicator success';
            } else if (status === 'failure' && timestamp) {
                indicator.textContent = `Offline (${this.formatTimeAgo(timestamp)})`;
                indicator.className = 'status-indicator failure';
            } else {
                indicator.textContent = 'Não testado';
                indicator.className = 'status-indicator unknown';
            }
        },

        updateAllPixStatusIndicators() {
            const providers = ['pushinpay', 'cnpay', 'oasyfy'];
            providers.forEach(provider => this.updatePixStatusIndicator(provider));
        },

        updatePixStatusIndicator(provider, mode) {
             const indicator = document.getElementById(`status-indicator-${provider}`);
            if (!indicator) return;

            if (mode === 'testing') {
                indicator.textContent = 'Testando...';
                indicator.className = 'status-indicator testing';
                return;
            }

            const status = localStorage.getItem(`pix_status_${provider}`);
            const timestamp = localStorage.getItem(`bot_timestamp_${provider}`);

            if (status === 'success' && timestamp) {
                indicator.textContent = `Ativo (Testado ${this.formatTimeAgo(timestamp)})`;
                indicator.className = 'status-indicator success';
            } else if (status === 'failure' && timestamp) {
                indicator.textContent = `Falhou (Testado ${this.formatTimeAgo(timestamp)})`;
                indicator.className = 'status-indicator failure';
            } else {
                indicator.textContent = 'Não testado';
                indicator.className = 'status-indicator unknown';
            }
        },

        formatTimeAgo(timestamp) {
            const seconds = Math.floor((Date.now() - timestamp) / 1000);
            if (seconds < 60) return "agora";
            const minutes = Math.floor(seconds / 60);
            if (minutes < 60) return `há ${minutes} min`;
            const hours = Math.floor(minutes / 60);
            if (hours < 24) return `há ${hours}h`;
            const days = Math.floor(hours / 24);
            return `há ${days}d`;
        },
        
        showToast(message, type = 'success') {
            const toast = document.createElement('div');
            let bgColor = type === 'success' ? 'bg-green-600' : 'bg-red-600';
            toast.className = `fixed bottom-5 right-5 ${bgColor} text-white py-2 px-4 rounded-lg shadow-lg animate-fade-in z-50`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.addEventListener('transitionend', () => toast.remove());
            }, 5000);
        },
        
        async loadBroadcastHistory(botId) {
            const historyEl = document.getElementById('broadcast-history');
            historyEl.innerHTML = '<p class="text-sm text-gray-400">Carregando histórico...</p>';
            try {
                const history = await this.apiRequest(`/api/broadcasts/${botId}`);
                if (history.length === 0) {
                    historyEl.innerHTML = '<p class="text-sm text-gray-500">Nenhuma campanha enviada para este bot.</p>';
                    return;
                }
                historyEl.innerHTML = history.map(item => `
                    <div class="p-3 bg-slate-900/50 rounded">
                        <p class="text-sm text-gray-300 truncate">${item.message_text}</p>
                        <div class="text-xs text-gray-500 mt-2 flex justify-between">
                            <span>${new Date(item.created_at).toLocaleString('pt-BR')}</span>
                            <span class="font-semibold ${item.status === 'completed' ? 'text-green-400' : 'text-yellow-400'}">
                                ${item.status}: ${item.sent_count}/${item.total_recipients} enviados | ${item.recovered_leads} recuperados
                            </span>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                historyEl.innerHTML = '<p class="text-sm text-red-400">Erro ao carregar histórico.</p>';
            }
        }
    };

    App.init();
    </script>
</body>
</html>
