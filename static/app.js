// SOCKS5 代理管理面板 - 前端逻辑

const API_BASE = '/api';

// 页面加载时获取数据
window.onload = function() {
    loadDashboard();
    loadUsers();
    loadGroups();
    setInterval(loadDashboard, 5000); // 每 5 秒刷新统计
};

// 加载仪表板数据
async function loadDashboard() {
    try {
        const res = await fetch(API_BASE + '/dashboard');
        const data = await res.json();
        document.getElementById('totalUsers').textContent = data.total_users || 0;
        document.getElementById('activeUsers').textContent = data.active_users || 0;
        document.getElementById('totalUpload').textContent = formatBytes(data.total_upload || 0);
        document.getElementById('totalDownload').textContent = formatBytes(data.total_download || 0);
    } catch (err) {
        console.error('加载仪表板失败:', err);
    }
}

// 加载用户列表
async function loadUsers() {
    try {
        const res = await fetch(API_BASE + '/users');
        const data = await res.json();
        console.log('API 返回数据:', data);
        
        // 处理可能的数组包装
        const users = Array.isArray(data) ? data : (data.value || []);
        console.log('解析后的用户列表:', users);
        
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';
        users.forEach(user => {
            console.log('处理用户:', user);
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.username || '未知'}</td>
                <td>${user.group || '-'}</td>
                <td>${formatSpeed(user.read_speed_limit)}</td>
                <td>${formatSpeed(user.write_speed_limit)}</td>
                <td>${user.max_connections || '∞'}</td>
                <td>${user.max_ip_connections || '∞'}</td>
                <td>${formatQuota(user.quota_period, user.quota_bytes, user.quota_used)}</td>
                <td>${user.enabled ? '✅' : '❌'}</td>
                <td>
                    <button class="btn" onclick="editUser('${user.username || ''}')">编辑</button>
                    <button class="btn btn-danger" onclick="deleteUser('${user.username || ''}')">删除</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('加载用户列表失败:', err);
    }
}

// 加载分组列表
async function loadGroups() {
    try {
        const res = await fetch(API_BASE + '/groups');
        const groups = await res.json();
        const tbody = document.getElementById('groupsTableBody');
        tbody.innerHTML = '';
        groups.forEach(group => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${group.name}</td>
                <td>${group.description || '-'}</td>
                <td>${formatSpeed(group.read_speed_limit)}</td>
                <td>${formatSpeed(group.write_speed_limit)}</td>
                <td>${group.max_connections || '∞'}</td>
                <td>${group.members}</td>
                <td>
                    <button class="btn" onclick="editGroup('${group.name}')">编辑</button>
                    <button class="btn btn-danger" onclick="deleteGroup('${group.name}')">删除</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
        
        // 更新分组选择框
        const select = document.getElementById('group');
        select.innerHTML = '<option value="">无分组</option>';
        groups.forEach(group => {
            select.innerHTML += `<option value="${group.name}">${group.name}</option>`;
        });
    } catch (err) {
        console.error('加载分组列表失败:', err);
    }
}

// 添加用户
document.getElementById('addUserForm').onsubmit = async function(e) {
    e.preventDefault();
    
    const editUsername = document.getElementById('editUsername').value;
    const isEdit = editUsername !== '';
    
    try {
        const userData = {
            username: document.getElementById('username').value,
            group: document.getElementById('group').value,
            read_limit: parseInt(document.getElementById('readLimit').value) || 0,
            write_limit: parseInt(document.getElementById('writeLimit').value) || 0,
            max_conn: parseInt(document.getElementById('maxConn').value) || 0,
            max_ip_connections: parseInt(document.getElementById('maxIPConnections').value) || 0
        };
        
        // 如果是编辑且密码不为空，才包含密码
        const password = document.getElementById('password').value;
        if (password) {
            userData.password = password;
        }
        
        console.log('提交用户数据:', userData);
        console.log('是否为编辑模式:', isEdit);
        
        if (isEdit) {
            // 更新用户
            const url = API_BASE + '/users?username=' + encodeURIComponent(editUsername);
            console.log('PUT 请求 URL:', url);
            console.log('PUT 请求数据:', JSON.stringify(userData));
            
            const response = await fetch(url, {
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
            
            // 更新流量配额（每次都更新，确保配额值正确）
            const quotaPeriod = document.getElementById('quotaPeriod').value;
            const quotaBytes = parseInt(document.getElementById('quotaBytes').value) * 1048576; // MB 转字节
            
            // 无论周期是否改变，都要更新配额值
            await fetch(API_BASE + '/user-quota?username=' + encodeURIComponent(editUsername), {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    period: quotaPeriod,
                    quota: quotaBytes
                })
            });
            console.log('流量配额已更新：周期=%s, 配额=%d MB', quotaPeriod, parseInt(document.getElementById('quotaBytes').value));
        } else {
            // 创建用户
            userData.password = password || 'temp123'; // 新用户必须有密码
            const response = await fetch(API_BASE + '/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(userData)
            });
            
            if (!response.ok) {
                throw new Error('创建失败');
            }
            
            // 设置流量配额
            const quotaPeriod = document.getElementById('quotaPeriod').value;
            const quotaBytes = parseInt(document.getElementById('quotaBytes').value) * 1048576; // MB 转字节
            
            if (quotaPeriod && quotaBytes > 0) {
                await fetch(API_BASE + '/user-quota?username=' + encodeURIComponent(userData.username), {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        period: quotaPeriod,
                        quota: quotaBytes
                    })
                });
            }
        }
        
        closeModal('addUserModal');
        resetUserForm();
        loadUsers();
    } catch (err) {
        console.error('操作失败:', err);
        alert('操作失败:' + err.message);
    }
};

// 添加分组
document.getElementById('addGroupForm').onsubmit = async function(e) {
    e.preventDefault();
    
    const groupName = document.getElementById('groupName').value;
    const isEdit = document.getElementById('editGroupName').value !== '';
    
    try {
        const groupData = {
            description: document.getElementById('groupDesc').value,
            read_limit: parseInt(document.getElementById('groupReadLimit').value) || 0,
            write_limit: parseInt(document.getElementById('groupWriteLimit').value) || 0,
            max_conn: parseInt(document.getElementById('groupMaxConn').value) || 0
        };
        
        if (isEdit) {
            // 更新分组
            const url = API_BASE + '/groups?name=' + encodeURIComponent(document.getElementById('editGroupName').value);
            const response = await fetch(url, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(groupData)
            });
            
            if (!response.ok) {
                const result = await response.text();
                throw new Error('更新失败：' + result);
            }
        } else {
            // 创建分组
            groupData.name = groupName;
            const response = await fetch(API_BASE + '/groups', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(groupData)
            });
            
            if (!response.ok) {
                throw new Error('创建失败');
            }
        }
        
        closeModal('addGroupModal');
        resetGroupForm();
        loadGroups();
    } catch (err) {
        console.error('操作失败:', err);
        alert('操作失败:' + err.message);
    }
};

// 删除用户
async function deleteUser(username) {
    if (!confirm('确定要删除用户 ' + username + ' 吗？')) return;
    await fetch(API_BASE + '/users?username=' + encodeURIComponent(username), {method: 'DELETE'});
    loadUsers();
}

// 删除分组
async function deleteGroup(name) {
    if (!confirm('确定要删除分组 ' + name + ' 吗？')) return;
    await fetch(API_BASE + '/groups?name=' + encodeURIComponent(name), {method: 'DELETE'});
    loadGroups();
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
    if (!period || total === 0) return '不限流量';
    const periodText = { 'daily': '每日', 'weekly': '每周', 'monthly': '每月' }[period] || '';
    return `${formatBytes(used)}/${formatBytes(total)} (${periodText})`;
}

function showModal(id) { document.getElementById(id).style.display = 'block'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }
function showAddUserModal() { showModal('addUserModal'); }
function showAddGroupModal() { showModal('addGroupModal'); }

// 重置表单函数
function resetUserForm() {
    document.getElementById('editUsername').value = '';
    document.getElementById('username').value = '';
    document.getElementById('username').readOnly = false;
    document.getElementById('password').value = '';
    document.getElementById('group').value = '';
    document.getElementById('readLimit').value = 0;
    document.getElementById('writeLimit').value = 0;
    document.getElementById('maxConn').value = 0;
    document.getElementById('quotaPeriod').value = '';
    document.getElementById('quotaBytes').value = 0;
    document.getElementById('quotaUsed').innerHTML = '<span style="color: #666;">未设置配额</span>';
    document.getElementById('userModalTitle').textContent = '添加用户';
}

function resetGroupForm() {
    document.getElementById('editGroupName').value = '';
    document.getElementById('groupName').value = '';
    document.getElementById('groupName').readOnly = false;
    document.getElementById('groupDesc').value = '';
    document.getElementById('groupReadLimit').value = 0;
    document.getElementById('groupWriteLimit').value = 0;
    document.getElementById('groupMaxConn').value = 0;
    document.getElementById('groupModalTitle').textContent = '添加分组';
}

// 编辑用户
async function editUser(username) {
    try {
        // 获取用户数据
        const res = await fetch(API_BASE + '/users');
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
        document.getElementById('group').value = user.group || '';
        document.getElementById('readLimit').value = user.read_speed_limit || 0;
        document.getElementById('writeLimit').value = user.write_speed_limit || 0;
        document.getElementById('maxConn').value = user.max_connections || 0;
        document.getElementById('maxIPConnections').value = user.max_ip_connections || 0;
        
        // 填充流量配额信息
        document.getElementById('quotaPeriod').value = user.quota_period || '';
        document.getElementById('quotaBytes').value = user.quota_bytes ? Math.floor(user.quota_bytes / 1048576) : 0;
        
        // 获取并显示已用流量
        await loadUserQuota(username);
        
        // 修改标题
        document.getElementById('userModalTitle').textContent = '编辑用户';
        
        // 显示模态框
        showModal('addUserModal');
    } catch (err) {
        alert('加载用户数据失败:' + err.message);
    }
}

// 加载用户流量配额信息
async function loadUserQuota(username) {
    try {
        const res = await fetch(API_BASE + '/user-quota?username=' + encodeURIComponent(username));
        const quota = await res.json();
        
        const quotaUsedDiv = document.getElementById('quotaUsed');
        if (quota.period && quota.total > 0) {
            const periodText = { 'daily': '每日', 'weekly': '每周', 'monthly': '每月' }[quota.period] || '';
            const resetDate = new Date(quota.reset_time * 1000).toLocaleDateString('zh-CN');
            quotaUsedDiv.innerHTML = `
                <div style="margin-bottom: 8px;">
                    <strong>已用：</strong>${formatBytes(quota.used)} / ${formatBytes(quota.total)}
                </div>
                <div style="font-size: 12px; color: #666;">
                    <strong>周期：</strong>${periodText} | <strong>重置：</strong>${resetDate}
                </div>
                <div style="margin-top: 5px;">
                    <div style="background: #e0e0e0; border-radius: 10px; height: 10px; overflow: hidden;">
                        <div style="background: ${quota.used / quota.total > 0.8 ? '#f44336' : '#4caf50'}; 
                                    width: ${Math.min((quota.used / quota.total) * 100, 100)}%; 
                                    height: 100%; transition: width 0.3s;"></div>
                    </div>
                </div>
            `;
        } else {
            quotaUsedDiv.innerHTML = '<span style="color: #666;">未设置配额</span>';
        }
    } catch (err) {
        console.error('加载配额信息失败:', err);
        document.getElementById('quotaUsed').innerHTML = '<span style="color: #666;">加载失败</span>';
    }
}

// 编辑分组
async function editGroup(name) {
    try {
        // 获取分组数据
        const res = await fetch(API_BASE + '/groups');
        const groups = await res.json();
        const group = groups.find(g => g.name === name);
        
        if (!group) {
            alert('分组不存在');
            return;
        }
        
        // 填充表单
        document.getElementById('editGroupName').value = group.name;
        document.getElementById('groupName').value = group.name;
        document.getElementById('groupName').readOnly = true;
        document.getElementById('groupDesc').value = group.description || '';
        document.getElementById('groupReadLimit').value = group.read_speed_limit || 0;
        document.getElementById('groupWriteLimit').value = group.write_speed_limit || 0;
        document.getElementById('groupMaxConn').value = group.max_connections || 0;
        
        // 修改标题
        document.getElementById('groupModalTitle').textContent = '编辑分组';
        
        // 显示模态框
        showModal('addGroupModal');
    } catch (err) {
        alert('加载分组数据失败:' + err.message);
    }
}


