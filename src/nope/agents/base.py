"""
NOPE Base Agent

This module provides the base agent class that all NOPE agents inherit from.
It defines the common interface and functionality for all agent types.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field

from nope.core.config import get_settings
from nope.core.exceptions import AgentError, AgentExecutionError, AgentTimeoutError


class AgentStatus(BaseModel):
    """Agent status model."""
    
    agent_id: str
    name: str
    type: str
    status: str  # idle, running, error, stopped
    last_update: datetime
    tasks_completed: int = 0
    tasks_failed: int = 0
    uptime: float = 0.0  # seconds
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True


class AgentTask(BaseModel):
    """Agent task model."""
    
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 0  # Higher number = higher priority
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True


class BaseAgent(ABC):
    """
    Base class for all NOPE agents.
    
    Provides common functionality including:
    - Task management and execution
    - Status tracking and reporting
    - Error handling and logging
    - Configuration management
    - Health monitoring
    """
    
    def __init__(
        self,
        name: str,
        agent_type: str,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize base agent.
        
        Args:
            name: Human-readable agent name
            agent_type: Agent type identifier
            config: Agent-specific configuration
        """
        self.agent_id = str(uuid4())
        self.name = name
        self.agent_type = agent_type
        self.config = config or {}
        self.settings = get_settings()
        
        # Set up logging
        self.logger = logging.getLogger(f"nope.agents.{self.agent_type}.{self.name}")
        
        # Initialize status
        self._status = AgentStatus(
            agent_id=self.agent_id,
            name=self.name,
            type=self.agent_type,
            status="idle",
            last_update=datetime.utcnow()
        )
        
        # Task management
        self._task_queue: List[AgentTask] = []
        self._current_task: Optional[AgentTask] = None
        self._running = False
        self._start_time = datetime.utcnow()
        
        self.logger.info(f"Initialized {self.agent_type} agent: {self.name}")
    
    @property
    def status(self) -> AgentStatus:
        """Get current agent status."""
        # Update uptime
        self._status.uptime = (datetime.utcnow() - self._start_time).total_seconds()
        self._status.last_update = datetime.utcnow()
        return self._status
    
    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize agent-specific resources.
        
        This method should be implemented by each agent to set up
        any resources, connections, or configurations needed.
        """
        pass
    
    @abstractmethod
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute a specific task.
        
        This method should be implemented by each agent to define
        the core task execution logic.
        
        Args:
            task: Task to execute
            
        Returns:
            Task execution results
            
        Raises:
            AgentExecutionError: If task execution fails
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """
        Clean up agent resources.
        
        This method should be implemented by each agent to clean up
        any resources, connections, or temporary data.
        """
        pass
    
    async def start(self) -> None:
        """Start the agent."""
        if self._running:
            self.logger.warning(f"Agent {self.name} is already running")
            return
        
        try:
            self.logger.info(f"Starting agent {self.name}")
            self._status.status = "running"
            self._running = True
            
            # Initialize agent
            await self.initialize()
            
            # Start task processing loop
            await self._task_loop()
            
        except Exception as e:
            self.logger.error(f"Error starting agent {self.name}: {e}")
            self._status.status = "error"
            raise AgentError(f"Failed to start agent {self.name}: {e}", agent_name=self.name)
    
    async def stop(self) -> None:
        """Stop the agent."""
        if not self._running:
            self.logger.warning(f"Agent {self.name} is not running")
            return
        
        try:
            self.logger.info(f"Stopping agent {self.name}")
            self._running = False
            self._status.status = "stopped"
            
            # Clean up resources
            await self.cleanup()
            
        except Exception as e:
            self.logger.error(f"Error stopping agent {self.name}: {e}")
            self._status.status = "error"
            raise AgentError(f"Failed to stop agent {self.name}: {e}", agent_name=self.name)
    
    async def add_task(self, task: AgentTask) -> None:
        """
        Add a task to the agent's queue.
        
        Args:
            task: Task to add
        """
        self.logger.debug(f"Adding task {task.task_id} to agent {self.name}")
        self._task_queue.append(task)
        
        # Sort by priority (higher priority first)
        self._task_queue.sort(key=lambda t: t.priority, reverse=True)
    
    async def get_tasks(self) -> List[AgentTask]:
        """Get all tasks in the queue."""
        return self._task_queue.copy()
    
    async def get_current_task(self) -> Optional[AgentTask]:
        """Get currently executing task."""
        return self._current_task
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check.
        
        Returns:
            Health check results
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "type": self.agent_type,
            "status": self._status.status,
            "running": self._running,
            "queue_size": len(self._task_queue),
            "current_task": self._current_task.task_id if self._current_task else None,
            "uptime": self._status.uptime,
            "tasks_completed": self._status.tasks_completed,
            "tasks_failed": self._status.tasks_failed,
        }
    
    async def _task_loop(self) -> None:
        """Main task processing loop."""
        while self._running:
            try:
                # Get next task
                if self._task_queue and not self._current_task:
                    task = self._task_queue.pop(0)
                    await self._execute_task_with_timeout(task)
                
                # Short sleep to prevent busy waiting
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in task loop for agent {self.name}: {e}")
                # Continue processing other tasks
                continue
    
    async def _execute_task_with_timeout(self, task: AgentTask) -> None:
        """
        Execute task with timeout handling.
        
        Args:
            task: Task to execute
        """
        self._current_task = task
        task.status = "running"
        task.started_at = datetime.utcnow()
        
        self.logger.info(f"Executing task {task.task_id}: {task.name}")
        
        try:
            # Execute with timeout
            timeout = self.config.get("task_timeout", self.settings.agent_timeout)
            result = await asyncio.wait_for(
                self.execute_task(task),
                timeout=timeout
            )
            
            # Task completed successfully
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.result = result
            self._status.tasks_completed += 1
            
            self.logger.info(f"Task {task.task_id} completed successfully")
            
        except asyncio.TimeoutError:
            # Task timed out
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            task.error = f"Task timed out after {timeout} seconds"
            self._status.tasks_failed += 1
            
            self.logger.error(f"Task {task.task_id} timed out")
            raise AgentTimeoutError(
                f"Task {task.task_id} timed out",
                agent_name=self.name,
                task_id=task.task_id,
                timeout_duration=timeout
            )
            
        except Exception as e:
            # Task failed with error
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            task.error = str(e)
            self._status.tasks_failed += 1
            
            self.logger.error(f"Task {task.task_id} failed: {e}")
            raise AgentExecutionError(
                f"Task {task.task_id} failed: {e}",
                agent_name=self.name,
                task_id=task.task_id
            )
            
        finally:
            self._current_task = None
    
    def __repr__(self) -> str:
        """String representation of the agent."""
        return f"{self.__class__.__name__}(name={self.name}, type={self.agent_type}, id={self.agent_id})"