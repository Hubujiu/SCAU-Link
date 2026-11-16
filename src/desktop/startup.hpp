#pragma once
#include <filesystem>
#include <string>

namespace scau::desktop {
std::wstring startup_task_name();
std::wstring startup_task_xml(const std::filesystem::path& executable, const std::wstring& user);
bool startup_task_enabled(const std::wstring& name);
void configure_startup_task(bool enabled, const std::filesystem::path& executable, const std::wstring& name);
void remove_owned_startup_task(const std::filesystem::path& executable, const std::wstring& name = {});
}
