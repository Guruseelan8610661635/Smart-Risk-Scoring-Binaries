// Dummy stats (replace with backend API later)
let stats = {
  malicious: 5,
  suspicious: 3,
  clean: 12
};

document.getElementById("maliciousCount").innerText = stats.malicious;
document.getElementById("suspiciousCount").innerText = stats.suspicious;
document.getElementById("cleanCount").innerText = stats.clean;
document.getElementById("totalScans").innerText =
  stats.malicious + stats.suspicious + stats.clean;

// Chart
const ctx = document.getElementById("threatChart");

new Chart(ctx, {
  type: "doughnut",
  data: {
    labels: ["Malicious", "Suspicious", "Clean"],
    datasets: [{
      data: [stats.malicious, stats.suspicious, stats.clean],
      backgroundColor: ["#dc3545", "#ffc107", "#198754"]
    }]
  }
});

// File upload (backend later)
function uploadFile() {
  const fileInput = document.getElementById("fileInput");
  const status = document.getElementById("uploadStatus");

  if (!fileInput.files.length) {
    status.innerText = "Please select a file first.";
    return;
  }

  status.innerText = "File uploaded (backend integration pending)";
}