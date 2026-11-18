/**
 * 网络批量配置器 - 全局核心 JavaScript 库 (main.js)
 */

// 1. Toast 消息通知提示
function showToast(message, type = 'info') {
    const toastEl = document.getElementById('appToast');
    if (!toastEl) {
        alert(message);
        return;
    }

    const toastMessage = document.getElementById('toastMessage');
    const toastIcon = document.getElementById('toastIcon');

    toastEl.className = 'toast align-items-center border-0 shadow';

    let iconClass = 'bi-info-circle-fill text-primary';
    let bgClass = 'bg-white';

    switch (type) {
        case 'success':
            iconClass = 'bi-check-circle-fill text-success';
            toastEl.classList.add('border-start', 'border-success', 'border-4');
            break;
        case 'error':
        case 'danger':
            iconClass = 'bi-exclamation-triangle-fill text-danger';
            toastEl.classList.add('border-start', 'border-danger', 'border-4');
            break;
        case 'warning':
            iconClass = 'bi-exclamation-circle-fill text-warning';
            toastEl.classList.add('border-start', 'border-warning', 'border-4');
            break;
        case 'info':
        default:
            iconClass = 'bi-info-circle-fill text-primary';
            toastEl.classList.add('border-start', 'border-primary', 'border-4');
            break;
    }

    if (toastIcon) {
        toastIcon.className = `bi ${iconClass} fs-5`;
    }
    if (toastMessage) {
        toastMessage.textContent = message;
    }

    const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 4000 });
    toast.show();
}

// 2. 通用 API 请求包装
async function apiCall(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Accept': 'application/json'
        }
    };

    const token = localStorage.getItem('auth_token');
    if (token) {
        options.headers['Authorization'] = 'Bearer ' + token;
    }

    if (data !== null && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
        if (typeof data === 'string') {
            options.headers['Content-Type'] = 'text/plain;charset=UTF-8';
            options.body = data;
        } else {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(data);
        }
    }

    try {
        const response = await fetch(url, options);
        let result;
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            result = await response.json();
        } else {
            result = await response.text();
        }

        if (!response.ok) {
            if (response.status === 401 && !url.includes('/api/auth/login')) {
                localStorage.removeItem('auth_token');
                window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
                return;
            }
            const errorMsg = (typeof result === 'object' && result !== null && (result.detail || result.error || result.message))
                ? (result.detail || result.error || result.message)
                : `请求失败: HTTP ${response.status} ${response.statusText}`;
            throw new Error(errorMsg);
        }

        return result;
    } catch (err) {
        console.error(`API 请求异常 [${method} ${url}]:`, err);
        throw err;
    }
}

// 身份快捷切换与注销
async function quickSwitchUser(username, password) {
    try {
        const res = await apiCall('/api/auth/login', 'POST', { username, password });
        if (res.token) localStorage.setItem('auth_token', res.token);
        showToast(`已切换身份为: ${res.user.display_name} (${res.user.role})`, 'success');
        setTimeout(() => window.location.reload(), 500);
    } catch (e) {
        showToast('切换失败: ' + e.message, 'error');
    }
}

async function userLogout() {
    try {
        await apiCall('/api/auth/logout', 'POST');
    } catch (e) {}
    localStorage.removeItem('auth_token');
    window.location.href = '/login';
}

// 3. 确认对话框
function confirmAction(message) {
    return window.confirm(message);
}

// 4. 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0 || bytes === '0' || !bytes) return '0 B';
    const numBytes = typeof bytes === 'string' ? parseInt(bytes, 10) : bytes;
    if (isNaN(numBytes) || numBytes <= 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(numBytes) / Math.log(k));
    return parseFloat((numBytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 5. 格式化日期时间
function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    try {
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) return dateStr;
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch (e) {
        return dateStr;
    }
}

// 6. 转义 HTML 实体
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// 7. 批量选中/反选复选框
function selectAllCheckboxes(selector, checked) {
    const checkboxes = document.querySelectorAll(selector);
    checkboxes.forEach(cb => {
        cb.checked = checked;
    });
}

// 8. 获取已选中的设备名称列表
function getSelectedDevices(selector) {
    const checkboxes = document.querySelectorAll(selector);
    const selected = [];
    checkboxes.forEach(cb => {
        if (cb.checked && cb.value) {
            selected.push(cb.value);
        }
    });
    return selected;
}

// 9. 按钮 Loading 加载状态切换
function showLoading(element, loadingText = '处理中...') {
    if (!element) return;
    element.dataset.originalHtml = element.innerHTML;
    element.disabled = true;
    element.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>${loadingText}`;
}

function hideLoading(element) {
    if (!element) return;
    if (element.dataset.originalHtml) {
        element.innerHTML = element.dataset.originalHtml;
    }
    element.disabled = false;
}

// 10. 辅助函数：根据设备类型渲染徽章
function renderDeviceTypeBadge(deviceType) {
    if (!deviceType) return '<span class="badge bg-secondary">未知</span>';
    const dt = String(deviceType).toLowerCase();
    if (dt.startsWith('huawei')) {
        return `<span class="badge badge-huawei"><i class="bi bi-hdd me-1"></i>${escapeHtml(deviceType)}</span>`;
    } else if (dt.startsWith('hp_comware') || dt.startsWith('h3c')) {
        return `<span class="badge badge-h3c"><i class="bi bi-hdd-network me-1"></i>${escapeHtml(deviceType)}</span>`;
    } else {
        return `<span class="badge badge-unknown">${escapeHtml(deviceType)}</span>`;
    }
}

// 11. 辅助函数：设备在线状态徽章
function renderDeviceStatusBadge(status, latencyMs = null, prompt = null) {
    if (status === 'online' || status === true) {
        const msText = latencyMs !== null && latencyMs !== undefined ? ` (${latencyMs}ms)` : '';
        const titleAttr = prompt ? ` title="提示符: ${escapeHtml(prompt)}"` : '';
        return `<span class="badge badge-status-online"${titleAttr}><i class="bi bi-check-circle-fill me-1"></i>在线${msText}</span>`;
    } else if (status === 'offline' || status === false) {
        return '<span class="badge badge-status-offline"><i class="bi bi-x-circle-fill me-1"></i>离线</span>';
    } else {
        return '<span class="badge badge-status-unknown"><i class="bi bi-question-circle me-1"></i>未知</span>';
    }
}
