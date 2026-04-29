# EdgeOne Demo Dashboard

MVP de demonstracao para cliente inserir dominio e visualizar metricas de DNS, SSL, latencia, HTTP e postura de seguranca.

## Funcionalidades

- Input de dominio e analise em tempo real.
- DNS: A/AAAA/CNAME/NS/MX e TTL.
- SSL/TLS: validade, emissor, dias restantes e versao TLS.
- Rede: latencia media por amostras de conexao TCP.
- HTTP: status code, TTFB, HSTS e CSP.
- Regiao: lookup geografico do IP principal.
- Seguranca: placeholders para WAF/DDoS integrando com API EdgeOne.

## Rodando local

```bash
npm install
npm run dev
```

Abra `http://localhost:3000`.

## Variaveis de ambiente

Copie `.env.example` para `.env`:

```bash
cp .env.example .env
```

- `PORT`: porta da aplicacao.
- `EDGEONE_API_BASE`: endpoint de agregacao com dados de WAF/DDoS.
- `EDGEONE_API_TOKEN`: token bearer para a API.

## Deploy no Render

1. Suba esse projeto no GitHub.
2. No Render, clique em **New + > Web Service**.
3. Conecte o repositorio e configure:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. Em **Environment Variables**, configure:
   - `PORT` = `10000` (opcional, Render define automaticamente)
   - `EDGEONE_API_BASE` e `EDGEONE_API_TOKEN` (se for usar WAF/DDoS reais)
5. Clique em **Create Web Service**.

## Sugestao de proximo passo

Criar um microservico autenticado que consulta APIs oficiais da Tencent Cloud EdgeOne e expoe um endpoint simplificado `/metrics?domain=...` para alimentar os campos WAF e DDoS deste dashboard.
