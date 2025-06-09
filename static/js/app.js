function showConnect() {
  const content = document.getElementById('content');
  content.innerHTML = '';
  const btn = document.createElement('a');
  btn.className = 'btn';
  btn.href = '/login';
  btn.textContent = 'Connect Creatio account';
  content.appendChild(btn);
}

function showDashboard(data) {
  const content = document.getElementById('content');
  content.innerHTML = '';
  if (data.user) {
    const info = document.createElement('p');
    const name = data.user.name || data.user.email || '';
    info.textContent = 'Logged in as ' + name;
    content.appendChild(info);
  }
  const canvas = document.createElement('canvas');
  canvas.id = 'activityChart';
  content.appendChild(canvas);

  if (data.activities && data.activities.length) {
    const list = document.createElement('ul');
    data.activities.forEach(a => {
      const li = document.createElement('li');
      li.textContent = a.Title;
      list.appendChild(li);
    });
    content.appendChild(list);
  }

  const labels = Object.keys(data.counts).sort();
  const values = labels.map(l => data.counts[l]);

  new Chart(document.getElementById('activityChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Activities by Month',
        data: values,
        backgroundColor: 'rgba(75,192,192,0.4)',
        borderColor: 'rgba(75,192,192,1)',
        borderWidth: 1
      }]
    },
    options: {
      scales: {
        y: { beginAtZero: true }
      }
    }
  });

  const actions = document.createElement('div');
  actions.innerHTML = `
      <a class="btn" href="/refresh">Refresh Token</a>
      <a class="btn" href="/logout">Logout</a>
      <a class="btn" href="/revoke">Revoke</a>
    `;
  content.appendChild(actions);
}

function loadData() {
  fetch('/api/activities')
    .then(resp => {
      if (resp.ok) {
        return resp.json().then(data => showDashboard(data));
      }
      showConnect();
    })
    .catch(() => showConnect());
}

document.addEventListener('DOMContentLoaded', loadData);
