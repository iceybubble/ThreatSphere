const BACKEND = "http://127.0.0.1:5000";
const API_KEY = "67b3a9472aa29263913b4db06c947773c3b21aff86bebd2156de015283ba01e2";

async function secureFetch(url) {
  return fetch(url, {
    headers: { "X-API-KEY": API_KEY }
  });
}

async function loadDashboard() {
  try {
    const [logsRes, categoriesRes, malwareRes] = await Promise.all([
      secureFetch(`${BACKEND}/logs/recent`),
      secureFetch(`${BACKEND}/categories`),
      secureFetch(`${BACKEND}/malware`)
    ]);

    const logs = await logsRes.json();
    const categories = await categoriesRes.json();
    const malware = await malwareRes.json();

    document.getElementById("totalLogs").innerText = `Total Logs: ${logs.length}`;
    document.getElementById("malwareCount").innerText = `Malware Detections: ${malware.length}`;
    document.getElementById("categoryCount").innerText = `Categories: ${Object.keys(categories).length}`;

    const tbody = document.querySelector("#logsTable tbody");
    tbody.innerHTML = "";
    logs.slice(0, 10).forEach(log => {
      tbody.innerHTML += `
        <tr>
          <td>${log.received_at}</td>
          <td>${log.category || "--"}</td>
          <td>${log.summary || "--"}</td>
          <td>${log.level || "--"}</td>
        </tr>`;
    });
  } catch (err) {
    console.error("Failed to load dashboard:", err);
  }
}

loadDashboard();
setInterval(loadDashboard, 10000);
