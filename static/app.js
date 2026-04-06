// SOCKS5 代理管理面板 - 前端逻辑

const API_BASE = '/api';
let authToken = localStorage.getItem('adminToken') || ''; // 使用 adminToken 作为 key
let currentUsername = localStorage.getItem('currentUsername') || '';

// 统一的 API 请求函数，自动处理 401 错误
async function apiFetch(url, options = {}) {
    // 如果没有指定 Content-Type，默认为 application/json
    if (!options.headers) {
        options.headers = {};
    }
    if (!options.headers['Content-Type'] && !options.headers['content-type']) {
        options.headers['Content-Type'] = 'application/json';
    }
    
    // 如果没有指定 X-Auth-Token，自动添加
    if (!options.headers['X-Auth-Token'] && !options.headers['x-auth-token']) {
        options.headers['X-Auth-Token'] = authToken;
    }
    
    console.log('[API 请求]', options.method || 'GET', url);
    
    const response = await fetch(url, options);
    
    // 处理 401 未授权
    if (response.status === 401) {
        console.error('[API 401] 会话已过期，跳转到登录页');
        localStorage.removeItem('adminToken');
        localStorage.removeItem('currentUsername');
        localStorage.removeItem('authToken');
        alert('⚠ 登录已过期，请重新登录');
        window.location.href = '/login.html';
        throw new Error('会话已过期');
    }
    
    // 处理其他错误状态
    if (!response.ok) {
        const errorText = await response.text();
        console.error('[API 错误]', response.status, errorText);
        throw new Error(`API 错误：${response.status} ${errorText}`);
    }
    
    return response;
}

// 检查 token 是否存在，不存在则跳转登录页
function checkTokenExists() {
    const token = localStorage.getItem('adminToken') || localStorage.getItem('authToken');
    if (!token) {
        console.error('[Token 检查] 未找到 token，跳转到登录页');
        window.location.href = '/login.html';
        return false;
    }
    authToken = token; // 更新全局 token
    return true;
}

// 页面加载时检查登录状态
window.onload = function() {
    checkLoginStatus();
};

// 检查登录状态
async function checkLoginStatus() {
    console.log('=== 开始检查登录状态 ===');
    console.log('Auth Token:', authToken ? '存在 (' + authToken.substring(0, 20) + '...)' : '不存在');
    
    if (!authToken) {
        console.log('⚠ 未登录，跳转到登录页');
        // 未登录，跳转到登录页
        window.location.href = '/login.html';
        return;
    }
    
    try {
        console.log('发送认证检查请求...');
        const res = await apiFetch(API_BASE + '/admin/check', {
            headers: {
                'X-Auth-Token': authToken  // 使用 X-Auth-Token header
            }
        });
        
        console.log('认证检查响应状态:', res.status);
        
        const data = await res.json();
        console.log('认证检查结果:', data);
        
        if (data.logged_in) {
            console.log('✅ 登录验证通过，用户名:', data.username);
            currentUsername = data.username;
            showMainPage();
            console.log('调用 loadDashboard()...');
            loadDashboard();
            console.log('调用 loadUsers()...');
            loadUsers();
            setInterval(loadDashboard, 5000); // 每 5 秒刷新统计
        } else {
            console.log('⚠ Token 无效，跳转到登录页');
            // Token 无效，跳转到登录页
            window.location.href = '/login.html';
        }
    } catch (err) {
        console.error('检查登录状态失败:', err);
        // apiFetch 已经处理了 401，这里只需要处理其他错误
        if (err.message !== '会话已过期') {
            window.location.href = '/login.html';
        }
    }
}

// 显示主页面（简化版，不再处理登录页）
function showMainPage() {
    if (currentUsername) {
        document.getElementById('currentUsername').textContent = currentUsername;
    }
}

// 处理登录表单提交（只在登录页面执行）
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    const captcha = document.getElementById('loginCaptcha').value;
    const captchaID = document.getElementById('captchaID').value;
    const errorDiv = document.getElementById('loginError');
    
    try {
        const res = await fetch(API_BASE + '/admin/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, captcha_id: captchaID, captcha: captcha })
        });
        
        const data = await res.json();
        
        if (res.ok && data.status === 'success') {
            // 保存 token 和用户名
            authToken = data.token;
            currentUsername = data.username;
            localStorage.setItem('adminToken', authToken);  // ✅ 统一使用 adminToken
            localStorage.setItem('currentUsername', currentUsername);
            
            // 隐藏错误信息
            errorDiv.style.display = 'none';
            
            // 显示主页面
            showMainPage();
            loadDashboard();
            loadUsers();
            setInterval(loadDashboard, 5000);
        } else {
            // 显示错误信息
            errorDiv.textContent = data.error || '用户名或密码错误';
            errorDiv.style.display = 'block';
            
            // 刷新验证码（任何登录失败都刷新）
            refreshCaptcha();
        }
    } catch (err) {
        console.error('登录失败:', err);
        errorDiv.textContent = '网络错误，请稍后重试';
        errorDiv.style.display = 'block';
    }
    });
}

// 登出函数
async function logout() {
    try {
        await apiFetch(API_BASE + '/admin/logout', {
            method: 'POST'
        });
    } catch (err) {
        console.error('登出失败:', err);
    }
    
    // 清除本地数据
    authToken = '';
    currentUsername = '';
    localStorage.removeItem('adminToken');
    localStorage.removeItem('currentUsername');
    
    // 跳转到登录页
    window.location.href = '/login.html';
}

// 刷新验证码
async function refreshCaptcha() {
    try {
        const res = await fetch(API_BASE + '/admin/captcha?t=' + Date.now());
        const blob = await res.blob();
        const imageUrl = URL.createObjectURL(blob);
        const captchaID = res.headers.get('X-Captcha-ID');
        
        document.getElementById('captchaImage').src = imageUrl;
        document.getElementById('captchaID').value = captchaID;
        document.getElementById('loginCaptcha').value = ''; // 清空验证码输入框
    } catch (err) {
        console.error('加载验证码失败:', err);
    }
}

// 显示修改密码模态框
function showChangePasswordModal() {
    document.getElementById('changePasswordError').style.display = 'none';
    document.getElementById('changePasswordForm').reset();
    showModal('changePasswordModal');
}

// 显示认证方式模态框
async function showAuthMethodModal() {
    const warningDiv = document.getElementById('authMethodWarning');
    warningDiv.style.display = 'none';
    
    // 加载当前认证方式
    try {
        const res = await apiFetch(API_BASE + '/admin/auth-method', {
            headers: {
                'X-Auth-Token': authToken  // ✅ 统一使用 X-Auth-Token
            }
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            // 设置单选按钮
            const radios = document.getElementsByName('authMethod');
            for (let radio of radios) {
                if (radio.value === data.auth_method) {
                    radio.checked = true;
                    break;
                }
            }
            
            // 显示模态框
            showModal('authMethodModal');
        } else {
            alert('加载认证方式失败：' + (data.error || '未知错误'));
        }
    } catch (err) {
        console.error('加载认证方式失败:', err);
        // apiFetch 已经处理了错误，这里不需要额外处理
    }
}

// 保存认证方式设置
async function saveAuthMethod() {
    const radios = document.getElementsByName('authMethod');
    let selectedMethod = '';
    
    for (let radio of radios) {
        if (radio.checked) {
            selectedMethod = radio.value;
            break;
        }
    }
    
    if (!selectedMethod) {
        const warningDiv = document.getElementById('authMethodWarning');
        warningDiv.textContent = '请选择认证方式';
        warningDiv.style.display = 'block';
        return;
    }
    
    // 如果选择无认证，显示警告
    if (selectedMethod === 'none') {
        const warningDiv = document.getElementById('authMethodWarning');
        warningDiv.innerHTML = '⚠️ <strong>警告：</strong>无认证模式不安全，任何人都可以连接和使用代理！确定要切换吗？';
        warningDiv.style.color = '#e74c3c';
        warningDiv.style.display = 'block';
        
        if (!confirm('⚠️ 警告：无认证模式不安全，任何人都可以连接和使用代理！\n\n确定要切换吗？')) {
            return;
        }
        warningDiv.style.display = 'none';
    }
    
    try {
        const res = await apiFetch(API_BASE + '/admin/auth-method', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': authToken  // ✅ 统一使用 X-Auth-Token
            },
            body: JSON.stringify({
                auth_method: selectedMethod
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert('✅ ' + data.message);
            closeModal('authMethodModal');
        } else {
            const warningDiv = document.getElementById('authMethodWarning');
            warningDiv.textContent = data.error || '设置失败';
            warningDiv.style.display = 'block';
        }
    } catch (err) {
        console.error('设置认证方式失败:', err);
        // apiFetch 已经处理了错误
    }
}

// 处理修改密码表单提交
document.getElementById('changePasswordForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const oldPassword = document.getElementById('oldPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const errorDiv = document.getElementById('changePasswordError');
    
    // 验证新密码
    if (newPassword.length < 6) {
        errorDiv.textContent = '密码长度至少为 6 位';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (newPassword !== confirmPassword) {
        errorDiv.textContent = '两次输入的新密码不一致';
        errorDiv.style.display = 'block';
        return;
    }
    
    try {
        const res = await apiFetch(API_BASE + '/admin/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': authToken  // ✅ 统一使用 X-Auth-Token
            },
            body: JSON.stringify({
                old_password: oldPassword,
                new_password: newPassword
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert('密码修改成功！请重新登录。');
            closeModal('changePasswordModal');
            logout();
        } else {
            errorDiv.textContent = data.error || '密码修改失败';
            errorDiv.style.display = 'block';
        }
    } catch (err) {
        console.error('修改密码失败:', err);
        // apiFetch 已经处理了错误
    }
});

// 加载仪表板数据
async function loadDashboard() {
    console.log('开始加载仪表板...');
    try {
        const res = await apiFetch(API_BASE + '/dashboard', {
            headers: {
                'X-Auth-Token': authToken  // 改为使用 X-Auth-Token header，与 loadUsers 保持一致
            }
        });
        
        console.log('仪表板响应状态:', res.status);
        
        const data = await res.json();
        console.log('仪表板数据:', data);
        
        document.getElementById('totalUsers').textContent = data.total_users || 0;
        document.getElementById('activeUsers').textContent = data.active_users || 0;
        document.getElementById('totalUpload').textContent = formatBytes(data.total_upload || 0);
        document.getElementById('totalDownload').textContent = formatBytes(data.total_download || 0);
        
        console.log('✅ 仪表板更新完成');
    } catch (err) {
        console.error('加载仪表板失败:', err);
        // apiFetch 已经处理了错误
    }
}

// 加载用户列表
async function loadUsers() {
    console.log('开始加载用户列表...');
    console.log('Auth Token:', authToken ? '存在' : '不存在');
    
    try {
        const res = await apiFetch(API_BASE + '/users', {
            headers: {
                'X-Auth-Token': authToken  // 使用 X-Auth-Token header
            }
        });
        
        console.log('响应状态:', res.status);
        
        const data = await res.json();
        console.log('API 返回数据:', data);
        console.log('数据类型:', Array.isArray(data) ? '数组' : '对象');
        
        // 处理可能的数组包装
        const users = Array.isArray(data) ? data : (data.value || []);
        console.log('解析后的用户列表:', users);
        console.log('用户数量:', users.length);
        
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';
        
        if (users.length === 0) {
            console.log('⚠ 没有用户数据');
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #999;">暂无用户</td></tr>';
            return;
        }
        
        users.forEach(user => {
            console.log('处理用户:', user);
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.username || '未知'}</td>
                <td>${formatSpeed(user.read_speed_limit)}</td>
                <td>${formatSpeed(user.write_speed_limit)}</td>
                <td>${user.max_connections || '∞'}</td>
                <td>${user.max_ip_connections || '∞'}</td>
                <td>${user.enabled ? '✅' : '❌'}</td>
                <td>
                    <button class="btn" onclick="editUser('${user.username || ''}')">编辑</button>
                    <button class="btn btn-danger" onclick="deleteUser('${user.username || ''}')">删除</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
        
        console.log('✅ 用户列表渲染完成');
    } catch (err) {
        console.error('加载用户列表失败:', err);
    }
}

// 加载分组列表（已删除）

// 添加用户
document.getElementById('addUserForm').onsubmit = async function(e) {
    e.preventDefault();
    
    const editUsername = document.getElementById('editUsername').value;
    const isEdit = editUsername !== '';
    
    try {
        const userData = {
            username: document.getElementById('username').value,
            read_limit: parseInt(document.getElementById('readLimit').value) || 0,
            write_limit: parseInt(document.getElementById('writeLimit').value) || 0,
            max_conn: parseInt(document.getElementById('maxConn').value) || 0,
            max_ip_connections: parseInt(document.getElementById('maxIPConnections').value) || 0
        };
        
        // 如果是编辑且密码不为空，才包含密码
        const password = document.getElementById('password').value;
        if (password) {
            // 密码校验
            if (password.length < 6) {
                alert('密码长度至少为 6 位');
                return;
            }
            
            // 检查是否包含空格
            if (/\s/.test(password)) {
                alert('密码不能包含空格');
                return;
            }
            
            // 检查密码强度（至少包含字母和数字）
            if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
                alert('密码必须包含字母和数字');
                return;
            }
            
            userData.password = password;
        }
        
        console.log('提交用户数据:', userData);
        console.log('是否为编辑模式:', isEdit);
        
        if (isEdit) {
            // 更新用户 - ✅ 使用 apiFetch 并添加 token
            const url = API_BASE + '/users?username=' + encodeURIComponent(editUsername);
            console.log('PUT 请求 URL:', url);
            
            console.log('PUT 请求数据:', JSON.stringify(userData));
            
            const response = await apiFetch(url, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(userData)
            });
            
            console.log('响应状态:', response.status);
            const result = await response.text();
            console.log('响应内容:', result);
            
            if (!response.ok) {
                throw new Error('更新失败：' + result);
            }
            
            console.log('用户信息已更新');
        } else {
            // 创建用户
            // 新用户必须有密码，且需要校验
            if (!password) {
                alert('请输入密码');
                return;
            }
            
            // 密码校验
            if (password.length < 6) {
                alert('密码长度至少为 6 位');
                return;
            }
            
            // 检查是否包含空格
            if (/\s/.test(password)) {
                alert('密码不能包含空格');
                return;
            }
            
            // 检查密码强度（至少包含字母和数字）
            if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
                alert('密码必须包含字母和数字');
                return;
            }
            
            userData.password = password;
            
            const response = await apiFetch(API_BASE + '/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(userData)
            });
        }
        
        closeModal('addUserModal');
        resetUserForm();
        loadUsers();
    } catch (err) {
        console.error('操作失败:', err);
        alert('操作失败:' + err.message);
    }
};

// 添加用户
async function deleteUser(username) {
    if (!confirm('确定要删除用户 ' + username + ' 吗？')) return;
    try {
        await apiFetch(API_BASE + '/users?username=' + encodeURIComponent(username), {
            method: 'DELETE'
        });
        loadUsers();
    } catch (err) {
        console.error('删除失败:', err);
        alert('删除用户失败：' + err.message);
    }
}

// 工具函数
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatSpeed(speed) {
    if (speed === 0) return '不限速';
    return formatBytes(speed) + '/s';
}

function formatQuota(period, total, used) {
    if (!period) return '不限流量';
    
    let periodText = '';
    if (period === 'custom') {
        periodText = '自定义时间段';
    } else {
        periodText = { 'daily': '每日', 'weekly': '每周', 'monthly': '每月' }[period] || '';
    }
    
    if (total === 0) {
        return `${formatBytes(used)} (${periodText})`;
    }
    
    return `${formatBytes(used)}/${formatBytes(total)} (${periodText})`;
}

function showModal(id) { document.getElementById(id).style.display = 'block'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }
function showAddUserModal() { showModal('addUserModal'); }
// showAddGroupModal 已删除

// 重置表单函数
function resetUserForm() {
    document.getElementById('editUsername').value = '';
    document.getElementById('username').value = '';
    document.getElementById('username').readOnly = false;
    document.getElementById('password').value = '';
    document.getElementById('readLimit').value = 0;
    document.getElementById('writeLimit').value = 0;
    document.getElementById('maxConn').value = 0;
    document.getElementById('maxIPConnections').value = 0;
    document.getElementById('userModalTitle').textContent = '添加用户';
}

// 编辑用户
async function editUser(username) {
    try {
        // 获取用户数据 - ✅ 使用 apiFetch 添加 token 验证
        const res = await apiFetch(API_BASE + '/users', {
            headers: {
                'X-Auth-Token': authToken
            }
        });
        const users = await res.json();
        const user = users.find(u => u.username === username);
        
        if (!user) {
            alert('用户不存在');
            return;
        }
        
        // 填充表单
        document.getElementById('editUsername').value = user.username;
        document.getElementById('username').value = user.username;
        document.getElementById('username').readOnly = true;
        document.getElementById('password').value = '';
        document.getElementById('readLimit').value = user.read_speed_limit || 0;
        document.getElementById('writeLimit').value = user.write_speed_limit || 0;
        document.getElementById('maxConn').value = user.max_connections || 0;
        document.getElementById('maxIPConnections').value = user.max_ip_connections || 0;
        
        // 修改标题
        document.getElementById('userModalTitle').textContent = '编辑用户';
        
        // 显示模态框
        showModal('addUserModal');
    } catch (err) {
        alert('加载用户数据失败:' + err.message);
    }
}

// 显示服务器配置模态框
async function showConfigModal() {
    const msgDiv = document.getElementById('configMessage');
    msgDiv.innerHTML = '';
    
    console.log('开始加载配置...');
    console.log('API_BASE:', API_BASE);
    console.log('authToken:', authToken ? '存在' : '不存在');
    
    // 加载当前配置 - ✅ 使用 apiFetch 统一处理
    try {
        const res = await apiFetch(API_BASE + '/admin/config', {
            headers: {
                'X-Auth-Token': authToken  // ✅ 统一使用 X-Auth-Token
            }
        });
        
        console.log('响应状态:', res.status);
        
        const data = await res.json();
        console.log('响应数据:', data);
        
        if (res.ok && data.status === 'success') {
            const config = data.config || {};
            console.log('配置对象:', config);
            
            // 填充表单字段
            document.getElementById('configListenAddr').value = config.listen_addr || '';
            document.getElementById('configMaxWorkers').value = config.max_workers || '';
            document.getElementById('configMaxConnPerIP').value = config.max_conn_per_ip || '';
            document.getElementById('configReadSpeedLimit').value = config.read_speed_limit || '';
            document.getElementById('configWriteSpeedLimit').value = config.write_speed_limit || '';
            document.getElementById('configTCPKeepAlive').value = config.tcp_keepalive_period || '';
            
            console.log('配置填充完成');
            
            // 显示模态框
            showModal('configModal');
        } else {
            console.error('加载配置失败:', data.error);
            alert('加载配置失败：' + (data.error || '未知错误'));
        }
    } catch (err) {
        console.error('加载配置异常:', err);
        alert('网络错误，请稍后重试');
    }
}

// 全局提交状态管理
const submitState = {
    isSubmitting: false,  // 是否正在提交
    lastSubmitTime: 0,    // 上次提交时间
    submitToken: '',      // 提交令牌
    minSubmitInterval: 1000  // 最小提交间隔（毫秒）
};

// 生成提交令牌
function generateSubmitToken() {
    return 'token_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
}

// 检查是否可以提交
function canSubmit() {
    const now = Date.now();
    
    // 检查是否正在提交
    if (submitState.isSubmitting) {
        console.log('正在提交中，请稍后...');
        return false;
    }
    
    // 检查提交间隔
    if (now - submitState.lastSubmitTime < submitState.minSubmitInterval) {
        console.log('提交过于频繁，请稍后...');
        return false;
    }
    
    // 生成新的提交令牌
    submitState.submitToken = generateSubmitToken();
    return true;
}

// 设置提交状态
function setSubmitting(isSubmitting) {
    submitState.isSubmitting = isSubmitting;
    if (isSubmitting) {
        submitState.lastSubmitTime = Date.now();
    }
}

// 禁用/启用按钮
function setButtonDisabled(selector, disabled) {
    const buttons = document.querySelectorAll(selector);
    buttons.forEach(btn => {
        btn.disabled = disabled;
        if (disabled) {
            btn.style.opacity = '0.6';
            btn.style.cursor = 'not-allowed';
        } else {
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
        }
    });
}

// 验证配置输入的前端函数
function validateConfigInput(config) {
    const errors = [];
    
    // 验证监听地址
    if (config.listen_addr) {
        const addrRegex = /^[0-9.:]+$/;
        if (!addrRegex.test(config.listen_addr)) {
            errors.push('❌ 监听地址只能包含数字、点和冒号');
        }
        if (config.listen_addr.length > 64) {
            errors.push('❌ 监听地址长度不能超过 64 个字符');
        }
        // 检查 IP:PORT 格式
        const parts = config.listen_addr.split(':');
        if (parts.length !== 2) {
            errors.push('❌ 监听地址格式应为 IP:PORT');
        } else {
            const port = parseInt(parts[1]);
            if (isNaN(port) || port < 1 || port > 65535) {
                errors.push('❌ 端口号必须在 1-65535 之间');
            }
        }
        // 检查 XSS 特征
        if (config.listen_addr.toLowerCase().includes('<script') || 
            config.listen_addr.toLowerCase().includes('javascript:')) {
            errors.push('❌ 监听地址包含非法内容');
        }
    }
    
    // 验证数值范围
    if (config.max_workers < 0 || config.max_workers > 10000) {
        errors.push('❌ 最大工作协程数必须在 0-10000 之间');
    }
    if (config.max_conn_per_ip < 0 || config.max_conn_per_ip > 65535) {
        errors.push('❌ 单 IP 最大连接数必须在 0-65535 之间');
    }
    if (config.read_speed_limit < 0 || config.read_speed_limit > 10737418240) {
        errors.push('❌ 上传速度限制过大');
    }
    if (config.write_speed_limit < 0 || config.write_speed_limit > 10737418240) {
        errors.push('❌ 下载速度限制过大');
    }
    if (config.tcp_keepalive_period < 0 || config.tcp_keepalive_period > 3600) {
        errors.push('❌ TCP Keepalive 周期必须在 0-3600 秒之间');
    }
    
    return errors;
}

// 保存服务器配置
async function saveConfig() {
    const msgDiv = document.getElementById('configMessage');
    
    // 检查是否可以提交
    if (!canSubmit()) {
        msgDiv.innerHTML = '<div class="alert alert-warning">⚠️ 提交过于频繁，请稍后...</div>';
        return;
    }
    
    // 禁用保存按钮
    setButtonDisabled('#configModal button[type="button"], #configModal .btn-primary', true);
    
    // 设置提交状态
    setSubmitting(true);
    
    // 收集表单数据
    const configData = {
        listen_addr: document.getElementById('configListenAddr').value.trim(),
        max_workers: parseInt(document.getElementById('configMaxWorkers').value) || 0,
        max_conn_per_ip: parseInt(document.getElementById('configMaxConnPerIP').value) || 0,
        read_speed_limit: parseInt(document.getElementById('configReadSpeedLimit').value) || 0,
        write_speed_limit: parseInt(document.getElementById('configWriteSpeedLimit').value) || 0,
        tcp_keepalive_period: parseInt(document.getElementById('configTCPKeepAlive').value) || 0
    };
    
    // 添加提交令牌
    configData.submit_token = submitState.submitToken;
    
    // 前端验证
    const errors = validateConfigInput(configData);
    if (errors.length > 0) {
        msgDiv.innerHTML = `<div class="alert alert-danger">${errors.join('<br>')}</div>`;
        setSubmitting(false);
        setButtonDisabled('#configModal button[type="button"], #configModal .btn-primary', false);
        return;
    }
    
    try {
        const res = await apiFetch(API_BASE + '/admin/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': authToken  // ✅ 统一使用 X-Auth-Token
            },
            body: JSON.stringify(configData)
        });
        
        const data = await res.json();
        
        if (res.ok && data.status === 'success') {
            msgDiv.innerHTML = '<div style="color: #27ae60; padding: 10px;">✅ ' + data.message + '</div>';
            setTimeout(() => {
                closeModal('configModal');
            }, 2000);
        } else {
            msgDiv.innerHTML = '<div style="color: #e74c3c; padding: 10px;">❌ ' + (data.error || '保存失败') + '</div>';
        }
    } catch (err) {
        console.error('保存配置失败:', err);
        msgDiv.innerHTML = '<div style="color: #e74c3c; padding: 10px;">❌ 网络错误，请稍后重试</div>';
    } finally {
        // 恢复提交状态和按钮
        setSubmitting(false);
        setButtonDisabled('#configModal button[type="button"], #configModal .btn-primary', false);
    }
}