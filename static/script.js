const BACKEND = "http://127.0.0.1:5000";

// Fetch and update all sections
async function loadDashboard() {
  try {
    const [logsRes, categoriesRes, malwareRes] = await Promise.all([
      fetch(`${BACKEND}/logs`),
      fetch(`${BACKEND}/categories`),
      fetch(`${BACKEND}/malware`)
    ]);

    const logs = await logsRes.json();
    const categories = await categoriesRes.json();
    const malware = await malwareRes.json();

    // Overview
    document.getElementById("totalLogs").innerText = `Total Logs: ${logs.length}`;
    document.getElementById("malwareCount").innerText = `Malware Detections: ${malware.length}`;
    document.getElementById("categoryCount").innerText = `Categories: ${Object.keys(categories).length}`;

    // Logs Table
    const tbody = document.querySelector("#logsTable tbody");
    tbody.innerHTML = "";
    logs.slice(-10).reverse().forEach(log => {
      const row = `<tr>
        <td>${log.timestamp || "--"}</td>
        <td>${log.category || "--"}</td>
        <td>${log.message || "--"}</td>
        <td>${log.type || "--"}</td>
      </tr>`;
      tbody.innerHTML += row;
    });

    // Malware List
    const malwareList = document.getElementById("malwareList");
    malwareList.innerHTML = "";
    malware.forEach(m => {
      const li = document.createElement("li");
      li.textContent = `${m.filename || "Unknown"} — ${m.threat || "Suspicious"}`;
      malwareList.appendChild(li);
    });
  } catch (err) {
    console.error("Failed to load dashboard:", err);
  }
}

// Reload every 10 seconds
loadDashboard();
setInterval(loadDashboard, 10000);
