# app/yaml_validator.py

import yaml
import re
from typing import Dict, List, Tuple, Any
from pathlib import Path
import json

class YAMLValidator:
    """YAML 파일 검증 및 보안 검사 클래스"""
    
    def __init__(self):
        self.security_rules = self._load_security_rules()
        self.ansible_schema = self._load_ansible_schema()
    
    def _load_security_rules(self) -> Dict[str, List[str]]:
        """보안 규칙 로드"""
        return {
            "dangerous_commands": [
                r"rm\s+-rf\s+/",
                r"dd\s+if=/dev/zero",
                r"mkfs\.",
                r"fdisk",
                r"format",
                r"del\s+/[qsf]",
                r"shutdown",
                r"reboot",
                r"halt",
                r"init\s+0",
                r"init\s+6",
                r"systemctl\s+poweroff",
                r"systemctl\s+reboot",
                r"curl.*\|\s*sh",
                r"wget.*\|\s*sh",
                r"nc\s+-[el]",
                r"netcat\s+-[el]",
                r"/bin/sh",
                r"/bin/bash",
                r"exec\s+",
                r"eval\s+",
                r"system\s*\(",
                r"os\.system",
                r"subprocess\.call",
                r"subprocess\.run",
                r"subprocess\.Popen"
            ],
            "dangerous_paths": [
                r"/etc/passwd",
                r"/etc/shadow",
                r"/etc/sudoers",
                r"/boot",
                r"/sys",
                r"/proc",
                r"/dev",
                r"\.ssh/",
                r"authorized_keys",
                r"id_rsa",
                r"id_dsa",
                r"\.key$",
                r"\.pem$"
            ],
            "suspicious_protocols": [
                r"ftp://",
                r"http://.*download",
                r"tftp://",
                r"telnet://"
            ],
            "dangerous_modules": [
                "shell",
                "raw",
                "script",
                "win_shell"
            ]
        }
    
    def _load_ansible_schema(self) -> Dict:
        """Ansible 플레이북 기본 스키마"""
        return {
            "required_fields": ["hosts"],
            "optional_fields": ["name", "tasks", "vars", "handlers", "roles", "become", "gather_facts"],
            "task_required": ["name"],
            "task_optional": ["when", "tags", "become", "register", "with_items", "loop"]
        }
    
    def validate_yaml_syntax(self, content: str) -> Tuple[bool, str, Dict]:
        """YAML 문법 검증"""
        try:
            parsed = yaml.safe_load(content)
            if parsed is None:
                return False, "빈 YAML 파일입니다.", {}
            return True, "YAML 문법이 올바릅니다.", parsed
        except yaml.YAMLError as e:
            error_msg = f"YAML 문법 오류: {str(e)}"
            line_num = getattr(e, 'problem_mark', None)
            if line_num:
                error_msg += f" (라인 {line_num.line + 1}, 컬럼 {line_num.column + 1})"
            return False, error_msg, {}
    
    def validate_ansible_structure(self, parsed_yaml: Dict) -> Tuple[bool, List[str]]:
        """Ansible 플레이북 구조 검증"""
        issues = []
        
        # 단일 플레이북인지 플레이북 리스트인지 확인
        playbooks = parsed_yaml if isinstance(parsed_yaml, list) else [parsed_yaml]
        
        for i, playbook in enumerate(playbooks):
            if not isinstance(playbook, dict):
                issues.append(f"플레이북 {i+1}: 딕셔너리 형태여야 합니다.")
                continue
            
            # 필수 필드 검사
            for required_field in self.ansible_schema["required_fields"]:
                if required_field not in playbook:
                    issues.append(f"플레이북 {i+1}: '{required_field}' 필드가 누락되었습니다.")
            
            # hosts 필드 검증
            if "hosts" in playbook:
                hosts = playbook["hosts"]
                if not isinstance(hosts, (str, list)):
                    issues.append(f"플레이북 {i+1}: 'hosts' 필드는 문자열 또는 리스트여야 합니다.")
            
            # tasks 검증
            if "tasks" in playbook:
                task_issues = self._validate_tasks(playbook["tasks"], i+1)
                issues.extend(task_issues)
        
        return len(issues) == 0, issues
    
    def _validate_tasks(self, tasks: Any, playbook_num: int) -> List[str]:
        """태스크 리스트 검증"""
        issues = []
        
        if not isinstance(tasks, list):
            issues.append(f"플레이북 {playbook_num}: 'tasks'는 리스트여야 합니다.")
            return issues
        
        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                issues.append(f"플레이북 {playbook_num}, 태스크 {i+1}: 딕셔너리 형태여야 합니다.")
                continue
            
            # name 필드 검사
            if "name" not in task:
                issues.append(f"플레이북 {playbook_num}, 태스크 {i+1}: 'name' 필드가 누락되었습니다.")
            
            # 모듈 검사 (name을 제외한 첫 번째 키가 보통 모듈명)
            module_keys = [k for k in task.keys() if k not in self.ansible_schema["task_optional"] + ["name"]]
            if not module_keys:
                issues.append(f"플레이북 {playbook_num}, 태스크 {i+1}: 실행할 모듈이 없습니다.")
        
        return issues
    
    def check_security_violations(self, content: str, parsed_yaml: Dict) -> Tuple[bool, List[str]]:
        """보안 위반 사항 검사"""
        violations = []
        
        # 1. 위험한 명령어 검사
        for pattern in self.security_rules["dangerous_commands"]:
            if re.search(pattern, content, re.IGNORECASE):
                violations.append(f"위험한 명령어 패턴 발견: {pattern}")
        
        # 2. 위험한 경로 접근 검사
        for pattern in self.security_rules["dangerous_paths"]:
            if re.search(pattern, content, re.IGNORECASE):
                violations.append(f"위험한 경로 접근 발견: {pattern}")
        
        # 3. 의심스러운 프로토콜 검사
        for pattern in self.security_rules["suspicious_protocols"]:
            if re.search(pattern, content, re.IGNORECASE):
                violations.append(f"의심스러운 프로토콜 사용: {pattern}")
        
        # 4. 위험한 Ansible 모듈 검사
        if isinstance(parsed_yaml, dict) or isinstance(parsed_yaml, list):
            self._check_dangerous_modules(parsed_yaml, violations)
        
        # 5. 권한 상승 검사
        if re.search(r'become:\s*true', content, re.IGNORECASE):
            if not re.search(r'become_method:\s*(sudo|su)', content, re.IGNORECASE):
                violations.append("권한 상승이 설정되었지만 안전한 방법이 명시되지 않았습니다.")
        
        # 6. 변수 주입 취약점 검사
        if re.search(r'\{\{.*\|.*shell.*\}\}', content):
            violations.append("셸 명령어 주입 가능성이 있는 변수 사용이 발견되었습니다.")
        
        return len(violations) == 0, violations
    
    def _check_dangerous_modules(self, data: Any, violations: List[str], path: str = ""):
        """재귀적으로 위험한 모듈 검사"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if key in self.security_rules["dangerous_modules"]:
                    violations.append(f"위험한 모듈 사용: {key} (위치: {current_path})")
                
                self._check_dangerous_modules(value, violations, current_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                self._check_dangerous_modules(item, violations, current_path)
    
    def validate_complete(self, content: str) -> Dict[str, Any]:
        """전체 검증 수행"""
        result = {
            "valid": False,
            "syntax_valid": False,
            "structure_valid": False,
            "security_valid": False,
            "syntax_error": "",
            "structure_issues": [],
            "security_violations": [],
            "parsed_yaml": {}
        }
        
        # 1. YAML 문법 검증
        syntax_valid, syntax_error, parsed_yaml = self.validate_yaml_syntax(content)
        result["syntax_valid"] = syntax_valid
        result["syntax_error"] = syntax_error
        result["parsed_yaml"] = parsed_yaml
        
        if not syntax_valid:
            return result
        
        # 2. Ansible 구조 검증
        structure_valid, structure_issues = self.validate_ansible_structure(parsed_yaml)
        result["structure_valid"] = structure_valid
        result["structure_issues"] = structure_issues
        
        # 3. 보안 검사
        security_valid, security_violations = self.check_security_violations(content, parsed_yaml)
        result["security_valid"] = security_valid
        result["security_violations"] = security_violations
        
        # 전체 유효성
        result["valid"] = syntax_valid and structure_valid and security_valid
        
        return result

# 전역 검증기 인스턴스
yaml_validator = YAMLValidator()