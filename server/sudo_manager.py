import uuid
import datetime
import logging

class SudoManager:
    def __init__(self):
        # In-memory storage for prototype: {request_id: {data}}
        self.requests = {}
        self.history = []  # List of completed sudo events for history
        self.max_history = 100  # Keep last 100 events per user
        self.expiration_seconds = 300 # 5 minutes

    def create_request(self, username, hostname=None, command=None):
        request_id = str(uuid.uuid4())
        self.requests[request_id] = {
            "username": username,
            "hostname": hostname,
            "command": command or "sudo",
            "status": "pending",
            "created_at": datetime.datetime.utcnow(),
            "approved_by": None,
            "approved_at": None
        }
        return request_id

    def get_request(self, request_id):
        self._cleanup()
        return self.requests.get(request_id)

    def approve_request(self, request_id, approver_username):
        req = self.get_request(request_id)
        if not req:
            return False
        
        if req['status'] != 'pending':
            return False

        # Verify approver matches requester? 
        # For now, yes. The user approves their own sudo.
        if req['username'] != approver_username:
             logging.warning(f"Sudo approval mismatch: Requester {req['username']} != Approver {approver_username}")
             # Strict: User must approve their own sudo.
             return False

        req['status'] = 'approved'
        req['approved_by'] = approver_username
        req['approved_at'] = datetime.datetime.utcnow()
        
        # Add to history
        self._add_to_history(req, request_id, 'approved')
        return True

    def deny_request(self, request_id, reason='denied'):
        """Deny a sudo request."""
        req = self.get_request(request_id)
        if not req:
            return False
        if req['status'] != 'pending':
            return False
        
        req['status'] = 'denied'
        req['deny_reason'] = reason
        req['denied_at'] = datetime.datetime.utcnow()
        
        # Add to history
        self._add_to_history(req, request_id, 'denied')
        return True

    def _add_to_history(self, req, request_id, result):
        """Add a completed sudo event to history."""
        event = {
            "id": request_id,
            "username": req['username'],
            "hostname": req.get('hostname', 'unknown'),
            "command": req.get('command', 'sudo'),
            "result": result,
            "created_at": req['created_at'].isoformat() + "Z",
            "completed_at": datetime.datetime.utcnow().isoformat() + "Z"
        }
        self.history.insert(0, event)  # Most recent first
        
        # Trim history to max size
        if len(self.history) > self.max_history:
            self.history = self.history[:self.max_history]

    def _cleanup(self):
        """Removes expired requests and marks them as timeout in history."""
        now = datetime.datetime.utcnow()
        expired = []
        for rid, data in self.requests.items():
            if (now - data['created_at']).total_seconds() > self.expiration_seconds:
                if data['status'] == 'pending':
                    # Record timeout in history
                    self._add_to_history(data, rid, 'timeout')
                expired.append(rid)
        
        for rid in expired:
            del self.requests[rid]

    def get_user_sudo_state(self, username):
        """Return pending, last_approved, last_denied for the user."""
        self._cleanup()
        
        pending = []
        last_approved = None
        last_denied = None
        
        for rid, data in self.requests.items():
            if data['username'] != username:
                continue
                
            req_info = {
                "id": rid,
                "server": data.get('hostname', 'unknown'),
                "time": data['created_at'].isoformat() + "Z"
            }
            
            if data['status'] == 'pending':
                pending.append(req_info)
            elif data['status'] == 'approved':
                if last_approved is None or data.get('approved_at', data['created_at']) > last_approved.get('_time', datetime.datetime.min):
                    req_info['_time'] = data.get('approved_at', data['created_at'])
                    last_approved = req_info
            elif data['status'] == 'denied':
                if last_denied is None or data.get('denied_at', data['created_at']) > last_denied.get('_time', datetime.datetime.min):
                    req_info['reason'] = data.get('deny_reason', 'unknown')
                    req_info['_time'] = data.get('denied_at', data['created_at'])
                    last_denied = req_info
        
        # Clean internal _time field
        if last_approved:
            del last_approved['_time']
        if last_denied:
            del last_denied['_time']
        
        return {
            "pending": pending,
            "last_approved": last_approved,
            "last_denied": last_denied
        }

    def get_user_sudo_history(self, username, limit=20):
        """Return sudo history for a user."""
        self._cleanup()  # Process any expired pending requests first
        
        user_history = [e for e in self.history if e['username'] == username]
        return user_history[:limit]

sudo_manager = SudoManager()
