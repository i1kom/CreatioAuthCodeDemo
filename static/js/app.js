Chart.register(ChartDataLabels);

// plugin to add extra margin between legend and chart area
const legendMargin = {
  id: 'legendMargin',
  beforeInit(chart, args, options) {
    const fit = chart.legend.fit;
    chart.legend.fit = function fitWithMargin() {
      fit.bind(chart.legend)();
      this.height += (options && options.margin) || 0;
    };
  }
};
Chart.register(legendMargin);
Chart.defaults.plugins.legendMargin = { margin: 24 };

function stringToColor(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const h = Math.abs(hash) % 360;
  return `hsl(${h},70%,50%)`;
}

function renderTopPanel(username, userId) {
  const panel = document.getElementById('top-panel');
  if (!panel) return;
  let avatar = panel.querySelector('.user-avatar');
  if (!avatar) {
    avatar = document.createElement('div');
    avatar.className = 'user-avatar';
    panel.appendChild(avatar);
  }
  avatar.textContent = username ? username.charAt(0).toUpperCase() : '';
  avatar.style.backgroundColor = stringToColor(String(userId));

  let menu = panel.querySelector('.user-menu');
  if (!menu) {
    menu = document.createElement('div');
    menu.className = 'user-menu';
    panel.appendChild(menu);
  }
  menu.innerHTML = '';
  const profileBtn = document.createElement('button');
  profileBtn.className = 'menu-btn';
  profileBtn.textContent = 'My profile';
  menu.appendChild(profileBtn);
  const logoutBtn = document.createElement('button');
  logoutBtn.className = 'menu-btn';
  logoutBtn.textContent = 'Logout';
  logoutBtn.addEventListener('click', () => {
    window.location.href = '/logout';
  });
  menu.appendChild(logoutBtn);

  avatar.onclick = e => {
    e.stopPropagation();
    menu.classList.toggle('show');
  };

  if (!panel.dataset.listener) {
    document.addEventListener('click', ev => {
      if (!menu.contains(ev.target) && ev.target !== avatar) {
        menu.classList.remove('show');
      }
    });
    panel.dataset.listener = 'true';
  }
}

function showPreloader() {
  const p = document.getElementById('preloader');
  if (p) p.classList.remove('hidden');
}

function hidePreloader() {
  const p = document.getElementById('preloader');
  if (p) p.classList.add('hidden');
}

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
    type: 'bar',
    data: {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
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
      layout: { padding: { bottom: 24 } },
      responsive: true
    }
  });

  return container;
}

function createVacationChart() {
  const container = document.createElement('div');
  container.className = 'chart-container pie-container';
  const title = document.createElement('h3');
  title.textContent = 'Vacation Days Left';
  container.appendChild(title);
  const wrapper = document.createElement('div');
  wrapper.className = 'pie-wrapper';
  const canvas = document.createElement('canvas');
  canvas.id = 'vacationChart';
  wrapper.appendChild(canvas);
  container.appendChild(wrapper);

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
      aspectRatio: 1,
      plugins: { datalabels: { color: '#000' } },
      layout: { padding: { bottom: 24 } }
    }
  });

  return container;
}

function createPdpChart() {
  const container = document.createElement('div');
  container.className = 'chart-container pie-container';
  const title = document.createElement('h3');
  title.textContent = 'PDP Tasks Closed';
  container.appendChild(title);
  const wrapper = document.createElement('div');
  wrapper.className = 'pie-wrapper';
  const canvas = document.createElement('canvas');
  canvas.id = 'pdpChart';
  wrapper.appendChild(canvas);
  container.appendChild(wrapper);

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
      aspectRatio: 1,
      plugins: { datalabels: { color: '#000' } },
      layout: { padding: { bottom: 24 } }
    }
  });
  return container;
}

function showConnect() {
  const content = document.getElementById('content');
  content.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'chart-grid';
  grid.appendChild(createBonusChart());
  const btnContainer = document.createElement('div');
  btnContainer.className = 'chart-container center-content';
  const btn = document.createElement('a');
  btn.className = 'btn';
  btn.href = window.LOGIN_URL || '/creatio/login';
  btn.innerHTML = '<img src="/static/img/сreatio_logo.png" class="logo-icon" alt="Creatio"> Connect Creatio account';
  btnContainer.appendChild(btn);
  const desc = document.createElement('p');
  desc.textContent = 'Connect your Creatio account to access integrated features and data.';
  btnContainer.appendChild(desc);
  grid.appendChild(btnContainer);
  grid.appendChild(createVacationChart());
  grid.appendChild(createPdpChart());
  content.appendChild(grid);
  const local = window.LOCAL_USER;
  if (local) {
    renderTopPanel(local.username, local.id);
  }
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
  grid.appendChild(createBonusChart());
  const activityContainer = document.createElement('div');
  activityContainer.className = 'chart-container';
  const actTitle = document.createElement('h3');
  actTitle.textContent = 'Calls by Month';
  activityContainer.appendChild(actTitle);
  const canvas = document.createElement('canvas');
  canvas.id = 'activityChart';
  activityContainer.appendChild(canvas);
  grid.appendChild(activityContainer);
  grid.appendChild(createVacationChart());
  grid.appendChild(createPdpChart());
  content.appendChild(grid);

  // Activity titles are no longer displayed

  const labels = Object.keys(data.counts).sort();
  const values = labels.map(l => data.counts[l]);

  new Chart(document.getElementById('activityChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Calls by Month',
        data: values,
        backgroundColor: 'rgba(255,165,0,0.4)',
        borderColor: 'rgba(255,165,0,1)',
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
      layout: { padding: { bottom: 24 } }
    }
  });

  const local = data.localUser || window.LOCAL_USER;
  if (local) {
    renderTopPanel(local.username, local.id);
  }
}

function loadData() {
  showPreloader();
  fetch('/api/activities')
    .then(resp => {
      hidePreloader();
      if (resp.ok) {
        return resp.json().then(data => showDashboard(data));
      }
      showConnect();
    })
    .catch(() => {
      hidePreloader();
      showConnect();
    });
}

document.addEventListener('DOMContentLoaded', () => {
  if (window.LOCAL_USER) {
    renderTopPanel(window.LOCAL_USER.username, window.LOCAL_USER.id);
  }
  loadData();
});
