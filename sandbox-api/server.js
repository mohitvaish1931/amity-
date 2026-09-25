import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

// Fake database
const users = {
  "customer_001": { id: "customer_001", customerName: "User A", phone: "555-0100", address: "123 Alpha St", internalUserId: "INT-A-999" },
  "customer_002": { id: "customer_002", customerName: "User B", phone: "555-0200", address: "456 Beta Ave", internalUserId: "INT-B-888" },
  "admin_001": { id: "admin_001", customerName: "Admin", phone: "555-0000", address: "HQ", internalUserId: "INT-ADMIN-000" }
};

const orders = {
  "order_101": { id: "order_101", customerId: "customer_001", status: "SHIPPED", amount: 150.00, customerName: "User A", phone: "555-0100", address: "123 Alpha St", internalUserId: "INT-A-999", paymentMetadata: "tok_visa_123" },
  "order_102": { id: "order_102", customerId: "customer_002", status: "PROCESSING", amount: 200.00, customerName: "User B", phone: "555-0200", address: "456 Beta Ave", internalUserId: "INT-B-888", paymentMetadata: "tok_mc_456" }
};

const invoices = {
  "invoice_101": { id: "invoice_101", orderId: "order_101", status: "PAID", amount: 150.00, paymentMetadata: "tok_visa_123" },
  "invoice_102": { id: "invoice_102", orderId: "order_102", status: "UNPAID", amount: 200.00, paymentMetadata: "tok_mc_456" }
};

// Mode configuration
// Default to vulnerable so the testing engine can detect issues.
const isVulnerable = process.env.VULNERABLE !== 'false'; 

// Simple authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Check API Key as fallback (some tests might use API Key scheme)
    const apiKey = req.headers['x-api-key'];
    if (apiKey && users[apiKey]) {
      req.user = users[apiKey];
      return next();
    }
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = authHeader.split(' ')[1];
  const user = users[token]; // For simplicity, token == user id
  if (!user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.user = user;
  next();
}

app.get('/users/:id', authenticate, (req, res) => {
  const targetUser = users[req.params.id];
  if (!targetUser) return res.status(404).json({ error: "Not found" });
  
  if (!isVulnerable && req.user.id !== req.params.id && req.user.id !== "admin_001") {
    return res.status(403).json({ error: "Forbidden" });
  }
  
  // Data exposure vulnerability: internalUserId is always returned if vulnerable
  const responseData = { ...targetUser };
  if (!isVulnerable && req.user.id !== "admin_001") {
     delete responseData.internalUserId;
  }
  
  res.json(responseData);
});

app.get('/orders/:id', authenticate, (req, res) => {
  const order = orders[req.params.id];
  if (!order) return res.status(404).json({ error: "Not found" });
  
  if (!isVulnerable && req.user.id !== order.customerId && req.user.id !== "admin_001") {
    return res.status(403).json({ error: "Forbidden" });
  }
  
  const responseData = { ...order };
  if (!isVulnerable && req.user.id !== "admin_001") {
     delete responseData.internalUserId;
     delete responseData.paymentMetadata;
  }
  
  res.json(responseData);
});

app.post('/orders', authenticate, (req, res) => {
  const orderId = `order_${Math.floor(Math.random()*1000)}`;
  orders[orderId] = { id: orderId, customerId: req.user.id, status: "NEW", amount: req.body.amount || 0 };
  res.status(201).json({ message: "Created", id: orderId });
});

app.get('/orders/:id/invoice', authenticate, (req, res) => {
  const invoice = Object.values(invoices).find(i => i.orderId === req.params.id);
  if (!invoice) return res.status(404).json({ error: "Not found" });
  
  const order = orders[req.params.id];
  if (!isVulnerable && req.user.id !== order.customerId && req.user.id !== "admin_001") {
    return res.status(403).json({ error: "Forbidden" });
  }
  
  const responseData = { ...invoice };
  if (!isVulnerable && req.user.id !== "admin_001") {
     delete responseData.paymentMetadata;
  }
  
  res.json(responseData);
});

app.post('/admin/refund', authenticate, (req, res) => {
  if (!isVulnerable && req.user.id !== "admin_001") {
    return res.status(403).json({ error: "Forbidden - Admins only" });
  }
  
  res.json({ message: "Refund processed" });
});

const PORT = process.env.PORT || 9000;
app.listen(PORT, () => {
  console.log(`Sandbox API running on http://127.0.0.1:${PORT} (Vulnerable: ${isVulnerable})`);
});
