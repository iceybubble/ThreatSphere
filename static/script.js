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

    if (!logsRes.ok) throw new Error("Logs unauthorized");
    const logs = await logsRes.json();
    const categories = await categoriesRes.json();
    const malware = await malwareRes.json();

    // Update overview cards
    document.getElementById("totalLogsCard").innerText = `Total Logs: ${logs.length}`;
    document.getElementById("malwareCard").innerText = `Malware Detections: ${malware.length}`;
    document.getElementById("categoryCard").innerText = `Categories: ${Object.keys(categories).length}`;

    // Update Latest Logs table
    const tbody = document.querySelector("#logsTable tbody");
    tbody.innerHTML = "";
    logs.slice(0, 10).forEach(log => {
      tbody.innerHTML += `
        <tr>
          <td>${log.received_at || "--"}</td>
          <td>${log.category || "--"}</td>
          <td>${log.summary || "--"}</td>
          <td>${log.level || "--"}</td>
        </tr>`;
    });

    // Update Malware section
    const malwareList = document.getElementById("malwareList");
    malwareList.innerHTML = "";
    malware.forEach(m => {
      const li = document.createElement("li");
      li.textContent = `${m.filename} — ${m.threat}`;
      malwareList.appendChild(li);
    });
  } catch (err) {
    console.error("Failed to load dashboard:", err);
  }
}

loadDashboard();
setInterval(loadDashboard, 10000);

// ========== Modal Logic ==========
function openModal(id) {
  document.getElementById(id).style.display = "flex";
}
function closeModal(id) {
  document.getElementById(id).style.display = "none";
}
document.querySelectorAll(".close").forEach(btn => {
  btn.addEventListener("click", e => closeModal(e.target.dataset.target));
});
window.onclick = e => {
  if (e.target.classList.contains("modal")) e.target.style.display = "none";
};

// ========== Click Handlers for Cards ==========
document.getElementById("totalLogsCard").addEventListener("click", async () => {
  const res = await secureFetch(`${BACKEND}/logs/recent`);
  const logs = await res.json();
  const body = document.getElementById("logsModalBody");
  body.innerHTML = logs.map(log =>
    `<tr>
      <td>${log.received_at || "--"}</td>
      <td>${log.category || "--"}</td>
      <td>${log.summary || "--"}</td>
      <td>${log.level || "--"}</td>
    </tr>`
  ).join("");
  openModal("logsModal");
});

document.getElementById("malwareCard").addEventListener("click", async () => {
  const res = await secureFetch(`${BACKEND}/malware`);
  const malware = await res.json();
  const body = document.getElementById("malwareModalBody");
  body.innerHTML = malware.map(m =>
    `<li>${m.filename || "Unknown"} — ${m.threat || "Suspicious"}</li>`
  ).join("");
  openModal("malwareModal");
});

document.getElementById("categoryCard").addEventListener("click", async () => {
  const res = await secureFetch(`${BACKEND}/categories`);
  const categories = await res.json();
  const body = document.getElementById("categoriesModalBody");
  body.innerHTML = Object.entries(categories)
    .map(([key, val]) => `<li>${key}: ${val.length} logs</li>`)
    .join("");
  openModal("categoriesModal");
});
