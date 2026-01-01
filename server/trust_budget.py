"""
Trust Budget Ledger

Experimental. Opt-in. Governance primitive. May change or be removed.

This module provides issuance-time accounting for certificate requests.
It does not provide runtime enforcement, monitoring, or attack detection.

Trust budgets are a governance mechanism to limit cumulative human authority
during certificate issuance, addressing operational fatigue and privilege
accumulation over time.
"""

import sqlite3
import os
import threading
from datetime import datetime, timedelta
from typing import Optional, Tuple

# Thread-local storage for connections
_local = threading.local()


class TrustBudgetLedger:
    """
    SQLite-backed ledger for trust budget accounting.
    
    Provides atomic transactions for budget checks and deductions.
    Disabled by default unless explicitly configured in policy.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the Trust Budget Ledger.
        
        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(_local, 'connection') or _local.connection is None:
            _local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            _local.connection.row_factory = sqlite3.Row
        return _local.connection
    
    def _init_db(self):
        """Initialize the database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Budget allocations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS budgets (
                budget_id TEXT PRIMARY KEY,
                initial_balance INTEGER NOT NULL,
                current_balance INTEGER NOT NULL,
                reset_interval_hours INTEGER,
                last_reset_at TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Transaction log for audit purposes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                budget_id TEXT NOT NULL,
                username TEXT NOT NULL,
                cost INTEGER NOT NULL,
                balance_before INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                request_id TEXT,
                FOREIGN KEY (budget_id) REFERENCES budgets(budget_id)
            )
        ''')
        
        conn.commit()
    
    def get_or_create_budget(
        self,
        budget_id: str,
        initial_balance: int,
        reset_interval_hours: Optional[int] = None
    ) -> dict:
        """
        Get an existing budget or create a new one.
        
        Args:
            budget_id: Unique identifier for the budget.
            initial_balance: Starting balance for new budgets.
            reset_interval_hours: Optional reset interval in hours.
            
        Returns:
            Budget record as a dictionary.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM budgets WHERE budget_id = ?', (budget_id,))
        row = cursor.fetchone()
        
        if row:
            budget = dict(row)
            # Check if reset is due
            if budget['reset_interval_hours'] and budget['last_reset_at']:
                last_reset = datetime.fromisoformat(budget['last_reset_at'])
                next_reset = last_reset + timedelta(hours=budget['reset_interval_hours'])
                if datetime.utcnow() >= next_reset:
                    # Perform reset
                    cursor.execute('''
                        UPDATE budgets 
                        SET current_balance = initial_balance, last_reset_at = ?
                        WHERE budget_id = ?
                    ''', (datetime.utcnow().isoformat(), budget_id))
                    conn.commit()
                    budget['current_balance'] = budget['initial_balance']
                    budget['last_reset_at'] = datetime.utcnow().isoformat()
            return budget
        
        # Create new budget
        now = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO budgets (budget_id, initial_balance, current_balance, reset_interval_hours, last_reset_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (budget_id, initial_balance, initial_balance, reset_interval_hours, now, now))
        conn.commit()
        
        return {
            'budget_id': budget_id,
            'initial_balance': initial_balance,
            'current_balance': initial_balance,
            'reset_interval_hours': reset_interval_hours,
            'last_reset_at': now,
            'created_at': now
        }
    
    def check_and_deduct(
        self,
        budget_id: str,
        cost: int,
        username: str,
        request_id: Optional[str] = None
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Atomically check budget and deduct cost if sufficient.
        
        Args:
            budget_id: The budget to deduct from.
            cost: The cost of the operation.
            username: The user making the request.
            request_id: Optional request identifier for audit.
            
        Returns:
            Tuple of (success, remaining_balance, error_message).
            If success is False, error_message contains the reason.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Begin exclusive transaction for atomicity
            cursor.execute('BEGIN EXCLUSIVE')
            
            cursor.execute('SELECT * FROM budgets WHERE budget_id = ?', (budget_id,))
            row = cursor.fetchone()
            
            if not row:
                conn.rollback()
                return (False, 0, f"Budget '{budget_id}' not found.")
            
            budget = dict(row)
            current_balance = budget['current_balance']
            
            # Check for reset
            next_reset_str = None
            if budget['reset_interval_hours'] and budget['last_reset_at']:
                last_reset = datetime.fromisoformat(budget['last_reset_at'])
                next_reset = last_reset + timedelta(hours=budget['reset_interval_hours'])
                next_reset_str = next_reset.isoformat()
                
                if datetime.utcnow() >= next_reset:
                    # Perform reset
                    current_balance = budget['initial_balance']
                    cursor.execute('''
                        UPDATE budgets 
                        SET current_balance = ?, last_reset_at = ?
                        WHERE budget_id = ?
                    ''', (current_balance, datetime.utcnow().isoformat(), budget_id))
            
            # Check if sufficient balance
            if current_balance < cost:
                conn.rollback()
                reset_info = f" Budget resets at {next_reset_str}." if next_reset_str else ""
                return (
                    False,
                    current_balance,
                    f"Trust budget exhausted. This request requires {cost} points; {current_balance} remain.{reset_info}"
                )
            
            # Deduct cost
            new_balance = current_balance - cost
            cursor.execute('''
                UPDATE budgets SET current_balance = ? WHERE budget_id = ?
            ''', (new_balance, budget_id))
            
            # Log transaction
            cursor.execute('''
                INSERT INTO transactions (budget_id, username, cost, balance_before, balance_after, timestamp, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (budget_id, username, cost, current_balance, new_balance, datetime.utcnow().isoformat(), request_id))
            
            conn.commit()
            return (True, new_balance, None)
            
        except Exception as e:
            conn.rollback()
            return (False, 0, f"Budget transaction failed: {str(e)}")
    
    def get_balance(self, budget_id: str) -> Optional[int]:
        """Get the current balance for a budget."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT current_balance FROM budgets WHERE budget_id = ?', (budget_id,))
        row = cursor.fetchone()
        
        return row['current_balance'] if row else None
    
    def get_transaction_history(self, budget_id: str, limit: int = 50) -> list:
        """Get recent transactions for a budget."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM transactions 
            WHERE budget_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (budget_id, limit))
        
        return [dict(row) for row in cursor.fetchall()]
