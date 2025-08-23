document.addEventListener("DOMContentLoaded", () => {
      const form = document.getElementById("repoForm");
      const loading = document.getElementById("loading");

      // Cards
      const totalFiles = document.getElementById("totalFiles");
      const totalLoc = document.getElementById("totalLoc");
      const vulnDensity = document.getElementById("vulnDensity");
      const riskScore = document.getElementById("riskScore");

      // Charts
      let severityChart, languageChart;
      const severityCtx = document.getElementById("severityChart").getContext("2d");
      const languageCtx = document.getElementById("languageChart").getContext("2d");

      // Lists/Table
      const hotspotFiles = document.getElementById("hotspotFiles");
      const vulnTable = document.getElementById("vulnTable");
      const aiWrap = document.getElementById("aiSuggestions");
      const aiCount = document.getElementById("aiCount");

      // Commits
      const totalCommits = document.getElementById("totalCommits");
      const contributorsCount = document.getElementById("contributorsCount");
      const topContributors = document.getElementById("topContributors");
      const largeCommitsCount = document.getElementById("largeCommitsCount");
      const largeCommits = document.getElementById("largeCommits");

      // Filter
      const searchBox = document.getElementById("searchBox");
      let currentIssues = [];

      // Render helpers
      function renderSeverityChart(dist) {
        const labels = ["ERROR", "WARNING", "INFO"];
        const data = labels.map(l => dist?.[l] ?? 0);
        if (severityChart) severityChart.destroy();
        severityChart = new Chart(severityCtx, {
          type: "doughnut",
          data: {
            labels,
            datasets: [{ data }]
          },
          options: {
            responsive: true,
            plugins: { legend: { position: "bottom" } }
          }
        });
      }

      function renderLanguageChart(langVulns) {
        const labels = Object.keys(langVulns || {});
        const data = Object.values(langVulns || {});
        if (languageChart) languageChart.destroy();
        languageChart = new Chart(languageCtx, {
          type: "bar",
          data: { labels, datasets: [{ label: "Vulns", data }] },
          options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { x: { ticks: { autoSkip: false } } }
          }
        });
      }

      function renderHotspots(list) {
        hotspotFiles.innerHTML = "";
        (list || []).forEach(h => {
          const li = document.createElement("li");
          li.textContent = `${h.file} (${h.count})`;
          hotspotFiles.appendChild(li);
        });
      }

      function renderVulnTable(issues) {
        vulnTable.innerHTML = "";
        (issues || []).forEach(v => {
          const tr = document.createElement("tr");
          tr.className = "border-b hover:bg-slate-50";
          tr.innerHTML = `
            <td class="p-2">${v.file}</td>
            <td class="p-2">${v.line}</td>
            <td class="p-2 font-semibold ${v.severity === "ERROR" ? "text-rose-700" : v.severity === "WARNING" ? "text-amber-700" : "text-slate-600"}">${v.severity}</td>
            <td class="p-2">${v.rule}</td>
            <td class="p-2">${v.message}</td>
          `;
          vulnTable.appendChild(tr);
        });
      }

      function renderAISuggestions(items) {
        aiWrap.innerHTML = "";
  aiCount.textContent = (items || []).length + " suggestions";

  (items || []).forEach(s => {
    const card = document.createElement("div");
    card.className = "rounded-lg border p-4 bg-gradient-to-br from-indigo-50 to-white shadow hover:shadow-md transition";

    card.innerHTML = `
      <div class="flex justify-between items-center mb-2">
        <div class="text-xs text-slate-500">${s.file}:${s.line} — ${s.rule}</div>
        <button onclick="navigator.clipboard.writeText(\`${s.suggestion_md.replace(/`/g, "\\`")}\`)" class="text-indigo-600 text-xs hover:underline">Copy</button>
      </div>
      <div class="prose prose-sm max-w-none">${marked.parse(s.suggestion_md || "")}</div>
    `;

    aiWrap.appendChild(card);
  });
      }

      // Filter logic
      function applyFilter() {
        const q = (searchBox.value || "").toLowerCase();
        const filtered = currentIssues.filter(i =>
          i.file.toLowerCase().includes(q) ||
          i.rule.toLowerCase().includes(q) ||
          i.severity.toLowerCase().includes(q)
        );
        renderVulnTable(filtered);
      }
      searchBox.addEventListener("input", applyFilter);

      // Add a tiny markdown renderer (safe minimal) for AI suggestions
      // If you prefer not to use a CDN, you can remove this and render plain text.
      const mdScript = document.createElement('script');
      mdScript.src = "https://cdn.jsdelivr.net/npm/marked/marked.min.js";
      document.body.appendChild(mdScript);

      // Submit handler
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const repoUrl = document.getElementById("repoUrl").value.trim();
        const includeAi = document.getElementById("includeAi").checked;

        if (!repoUrl) {
          alert("Please enter a repository URL");
          return;
        }

        loading.classList.remove("hidden");

        try {
          const res = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ repo_url: repoUrl, include_ai: includeAi })
          });

          if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
          const data = await res.json();

          // Cards
          totalFiles.textContent = data.code_metrics?.total_files ?? "—";
          totalLoc.textContent = data.code_metrics?.total_lines_of_code ?? "—";
          vulnDensity.textContent = data.code_metrics?.vulnerability_density ?? "—";
          riskScore.textContent = data.code_metrics?.risk_score ?? "—";

          // Charts & lists
          renderSeverityChart(data.static_analysis?.severity_distribution || {});
          renderLanguageChart(data.static_analysis?.language_vulns || {});
          renderHotspots(data.static_analysis?.hotspots || []);

          // Table
          currentIssues = data.static_analysis?.issues || [];
          renderVulnTable(currentIssues);

          // AI
          renderAISuggestions(data.ai_suggestions || []);

          // Commits
          const co = data.commit_overview || {};
          totalCommits.textContent = co.total_commits ?? "—";
          contributorsCount.textContent = co.contributors_count ?? "—";
          topContributors.innerHTML = "";
          (co.top_contributors || []).forEach(c => {
            const li = document.createElement("li");
            li.textContent = c;
            topContributors.appendChild(li);
          });
          largeCommitsCount.textContent = co.large_commits_count ?? "—";
          largeCommits.innerHTML = "";
          (co.large_commits || []).forEach(c => {
            const li = document.createElement("li");
            li.textContent = `${(c.hash || "").slice(0, 7)} — ${c.message || ""} (+/- ${c.lines_changed || 0})`;
            largeCommits.appendChild(li);
          });

        } catch (err) {
          alert("❌ " + (err?.message || "Failed to analyze"));
        } finally {
          loading.classList.add("hidden");
        }
      });
    });