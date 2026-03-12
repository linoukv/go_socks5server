package main

import (
	"time"
)

// group_management.go - 用户分组管理功能

// CreateGroup 创建用户分组
func (a *PasswordAuth) CreateGroup(name, description string, readLimit, writeLimit int64, maxConn int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.groups[name]; exists {
		return false // 分组已存在
	}

	a.groups[name] = &UserGroup{
		Name:            name,
		Description:     description,
		ReadSpeedLimit:  readLimit,
		WriteSpeedLimit: writeLimit,
		MaxConnections:  maxConn,
		Members:         0,
	}
	return true
}

// RemoveGroup 删除用户分组
func (a *PasswordAuth) RemoveGroup(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.groups[name]; !exists {
		return false // 分组不存在
	}

	// 将组成员移动到默认组
	for _, user := range a.users {
		if user.Group == name {
			user.Group = ""
		}
	}

	delete(a.groups, name)
	return true
}

// GetGroup 获取分组信息
func (a *PasswordAuth) GetGroup(name string) (*UserGroup, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	group, exists := a.groups[name]
	return group, exists
}

// ListGroups 列出所有分组
func (a *PasswordAuth) ListGroups() []*UserGroup {
	a.mu.RLock()
	defer a.mu.RUnlock()

	groups := make([]*UserGroup, 0, len(a.groups))
	for _, group := range a.groups {
		groups = append(groups, group)
	}
	return groups
}

// UpdateGroup 更新分组配置
func (a *PasswordAuth) UpdateGroup(name, description string, readLimit, writeLimit int64, maxConn int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	group, exists := a.groups[name]
	if !exists {
		return false
	}

	group.Description = description
	group.ReadSpeedLimit = readLimit
	group.WriteSpeedLimit = writeLimit
	group.MaxConnections = maxConn
	return true
}

// AddUserToGroup 将用户添加到分组
func (a *PasswordAuth) AddUserToGroup(username, groupName string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, userExists := a.users[username]
	if !userExists {
		return false // 用户不存在
	}

	_, groupExists := a.groups[groupName]
	if !groupExists {
		return false // 分组不存在
	}

	// 如果用户原来在其他组，减少原组的成员数
	if user.Group != "" {
		if oldGroup, exists := a.groups[user.Group]; exists {
			oldGroup.Members--
		}
	}

	// 添加到新组
	user.Group = groupName
	a.groups[groupName].Members++
	return true
}

// RemoveUserFromGroup 将用户从分组移除
func (a *PasswordAuth) RemoveUserFromGroup(username string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	if user.Group != "" {
		if group, groupExists := a.groups[user.Group]; groupExists {
			group.Members--
		}
		user.Group = ""
		return true
	}
	return false
}

// ApplyGroupSettings 应用分组设置到组内所有用户
func (a *PasswordAuth) ApplyGroupSettings(groupName string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	group, exists := a.groups[groupName]
	if !exists {
		return false
	}

	// 遍历所有用户，更新属于该分组的用户设置
	for _, user := range a.users {
		if user.Group == groupName {
			user.ReadSpeedLimit = group.ReadSpeedLimit
			user.WriteSpeedLimit = group.WriteSpeedLimit
			user.MaxConnections = group.MaxConnections
		}
	}
	return true
}

// GetUserGroup 获取用户所在分组
func (a *PasswordAuth) GetUserGroup(username string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return "", false
	}
	return user.Group, true
}

// UpdateUserTraffic 更新用户流量统计
func (a *PasswordAuth) UpdateUserTraffic(username string, upload, download int64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if user, exists := a.users[username]; exists {
		user.UploadTotal += upload
		user.DownloadTotal += download
		user.LastActivity = time.Now().Unix()
	}
}

// ListUsersByGroup 按分组列出用户
func (a *PasswordAuth) ListUsersByGroup(groupName string) []*User {
	a.mu.RLock()
	defer a.mu.RUnlock()

	users := make([]*User, 0)
	for _, user := range a.users {
		if user.Group == groupName {
			users = append(users, user)
		}
	}
	return users
}

// GetGroupStats 获取分组统计信息
func (a *PasswordAuth) GetGroupStats(groupName string) (totalUsers, activeUsers int, totalUpload, totalDownload int64) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, user := range a.users {
		if user.Group == groupName {
			totalUsers++
			if user.LastActivity > time.Now().Unix()-3600 { // 1 小时内活跃
				activeUsers++
			}
			totalUpload += user.UploadTotal
			totalDownload += user.DownloadTotal
		}
	}
	return
}
