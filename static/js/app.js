Chart.register(ChartDataLabels);

function createBonusChart() {
  const container = document.createElement('div');
  container.className = 'chart-container';
  const title = document.createElement('h3');
  title.textContent = 'Bonuses This Year';
  container.appendChild(title);
  const canvas = document.createElement('canvas');
  canvas.id = 'bonusChart';
  container.appendChild(canvas);
  new Chart(canvas.getContext('2d'), {
  return container;
}

function createVacationChart() {
  const container = document.createElement('div');
  container.className = 'chart-container';
  const title = document.createElement('h3');
  title.textContent = 'Vacation Days Left';
  container.appendChild(title);
  const canvas = document.createElement('canvas');
  canvas.id = 'vacationChart';
  container.appendChild(canvas);

  new Chart(canvas.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Used', 'Left'],
      datasets: [{
        data: [12, 13],
        backgroundColor: ['#FF6384', '#36A2EB']
      }]
    },
    options: {
      responsive: true,
      plugins: { datalabels: { color: '#000' } }
    }
  });

  return container;
}

function createPdpChart() {
  const container = document.createElement('div');
  container.className = 'chart-container';
  const title = document.createElement('h3');
  title.textContent = 'PDP Tasks Closed';
  container.appendChild(title);
  const canvas = document.createElement('canvas');
  canvas.id = 'pdpChart';
  container.appendChild(canvas);

  new Chart(canvas.getContext('2d'), {
    type: 'pie',
    data: {
      labels: ['Closed', 'Open'],
      datasets: [{
        data: [80, 20],
        backgroundColor: ['#4BC0C0', '#FFCE56']
      }]
    },
    options: {
      responsive: true,
      plugins: { datalabels: { color: '#000' } }
    }
  });
  return container;
  grid.appendChild(createBonusChart());
  const btnContainer = document.createElement('div');
  btnContainer.className = 'chart-container center-content';
  btn.href = window.LOGIN_URL || '/login';
  btnContainer.appendChild(btn);
  grid.appendChild(btnContainer);
  grid.appendChild(createVacationChart());
  grid.appendChild(createPdpChart());
  grid.appendChild(createBonusChart());
  grid.appendChild(createVacationChart());
  grid.appendChild(createPdpChart());
      datasets: [{
        label: 'Bonuses',
        data: [100, 150, 120, 200, 180, 220, 170, 190, 160, 210, 230, 250],
        backgroundColor: 'rgba(75,192,192,0.4)',
        borderColor: 'rgba(75,192,192,1)',
        borderWidth: 1
      }]
    },
    options: {
      scales: {
        y: { beginAtZero: true }
      },

      plugins: {
        datalabels: {
          anchor: 'end',
          align: 'top',
          color: '#000'
        }
      },
      responsive: true
    }
  });

  return fragment;
}

function showConnect() {
  const content = document.getElementById('content');
  content.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'chart-grid';
  const container = document.createElement('div');
  container.className = 'chart-container center-content';
  const btn = document.createElement('a');
  btn.className = 'btn';
  btn.href = '/login';
  btn.textContent = 'Connect Creatio account';
  container.appendChild(btn);
  grid.appendChild(container);
  grid.appendChild(createStaticCharts());
  content.appendChild(grid);
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
  const grid = document.createElement('div');
  grid.className = 'chart-grid';
  const activityContainer = document.createElement('div');
  activityContainer.className = 'chart-container';
  const actTitle = document.createElement('h3');
  actTitle.textContent = 'Activities by Month';
  activityContainer.appendChild(actTitle);
  const canvas = document.createElement('canvas');
  canvas.id = 'activityChart';
  activityContainer.appendChild(canvas);
  grid.appendChild(activityContainer);
  grid.appendChild(createStaticCharts());
  content.appendChild(grid);

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
      },
      plugins: {
        datalabels: {
          anchor: 'end',
          align: 'top',
          color: '#000'
        }
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
