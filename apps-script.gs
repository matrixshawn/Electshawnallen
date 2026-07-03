// ============================================================
// Ward 25 Survey — Google Sheets Backend
// ============================================================
// 1. Open https://sheets.new
// 2. Extensions → Apps Script
// 3. Paste this entire file
// 4. Deploy → New Deployment → Web App → Execute as: Me, Who has access: Anyone
// 5. Copy the URL and paste it into config.js
// ============================================================

var SHEET_NAME = 'Sheet1';

function doPost(e) {
  return handleRequest(e);
}

function doGet(e) {
  return handleRequest(e);
}

function handleRequest(e) {
  var action = e.parameter.action;
  var data = e.parameter;
  
  if (action === 'login')    return doLogin(data);
  if (action === 'survey')   return doSurvey(data);
  if (action === 'dashboard') return doDashboard(data);
  if (action === 'stats')    return doStats(data);
  
  return json({ ok: false, error: 'Unknown action' });
}

function doLogin(data) {
  var name = data.name || 'Canvasser';
  var pin  = data.pin || '';
  if (!pin) return json({ ok: false, error: 'PIN required' });
  
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Canvassers') || 
              SpreadsheetApp.getActiveSpreadsheet().insertSheet('Canvassers');
  
  // Simple PIN auth — find or create canvasser
  var rows = sheet.getDataRange().getValues();
  var existing = null;
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][1]) === String(pin)) { existing = { row: i+1, name: rows[i][0] }; break; }
  }
  
  if (existing) {
    // Existing canvasser — update last login
    sheet.getRange(existing.row, 3).setValue(new Date());
    return json({ ok: true, token: pin, name: existing.name });
  }
  
  // New canvasser
  sheet.appendRow([name, pin, new Date()]);
  return json({ ok: true, token: pin, name: name });
}

function doSurvey(data) {
  var token = data.token || '';
  if (!token) return json({ ok: false, error: 'Not logged in' });
  
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Surveys') ||
              SpreadsheetApp.getActiveSpreadsheet().insertSheet('Surveys');
  
  // Set up headers if empty
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(['Timestamp', 'Canvasser', 'Address', 'Eligible Voters', 'Voter Name', 'Phone', 'Email',
      'Q1 Years in Ward', 'Q2 Top Issues', 'Q2 Other', 'Q3 Downsize', 'Q4 Chow Rating', 'Q5 Fair Share',
      'Q6 Lives in Ward', 'Q7 Heard of Shawn', 'Q8 Voting Plan', 'Q9 Support', 'Q10 Involvement',
      'Q11 Street Concern', 'Canvasser Notes', 'Follow-up Needed']);
  }
  
  sheet.appendRow([
    new Date(),
    getCanvasserName(token),
    data.address || '',
    parseInt(data.eligible_voters) || 0,
    data.voter_name || '',
    data.phone || '',
    data.email || '',
    data.years_in_ward || '',
    data.top_issue || '',
    data.top_issue_other || '',
    data.downsize_home || '',
    data.chow_rating || '',
    data.fair_share || '',
    data.lives_in_ward || '',
    data.heard_of_shawn || '',
    data.voting_plan || '',
    data.decided_support || '',
    data.involvement || '',
    data.street_concern || '',
    data.canvasser_notes || '',
    data.followup_needed || ''
  ]);
  
  return json({ ok: true });
}

function doDashboard(data) {
  var token = data.token || '';
  if (!token) return json({ ok: false, error: 'Not logged in' });
  
  var currentName = getCanvasserName(token);
  var surveySheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Surveys');
  var rows = surveySheet ? surveySheet.getDataRange().getValues() : [];
  
  // Stats for current user
  var userTotal = 0, userVoters = 0, userSigned = 0, userVolunteers = 0;
  var users = {}; // name -> {total, voters}
  var recent = [];
  
  for (var i = 1; i < rows.length; i++) {
    var row = rows[i];
    var name = row[1];
    var voters = parseInt(row[3]) || 0;
    var support = row[16] || '';
    var involvement = row[17] || '';
    
    if (!users[name]) users[name] = { total: 0, voters: 0 };
    users[name].total++;
    users[name].voters += voters;
    
    if (name === currentName) {
      userTotal++;
      userVoters += voters;
      if (support.indexOf('Shawn') > -1) userSigned++;
      if (involvement.indexOf('Volunteer') > -1) userVolunteers++;
      if (recent.length < 10) {
        recent.push({
          voter_name: row[4],
          address: row[2],
          decided_support: support,
          timestamp: row[0]
        });
      }
    }
  }
  
  // Leaderboard sorted by total surveys
  var leaderboard = Object.entries(users).map(function(e) {
    return { name: e[0], total: e[1].total, voters: e[1].voters };
  });
  leaderboard.sort(function(a, b) { return b.total - a.total; });
  
  return json({
    ok: true,
    total: userTotal,
    voters: userVoters,
    signed: userSigned,
    volunteers: userVolunteers,
    leaderboard: leaderboard,
    recent: recent
  });
}

function doStats(data) {
  var surveySheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Surveys');
  if (!surveySheet) return json({ ok: false, error: 'No surveys yet' });
  var rows = surveySheet.getDataRange().getValues();
  var totalVoters = 0;
  for (var i = 1; i < rows.length; i++) {
    totalVoters += parseInt(rows[i][3]) || 0;
  }
  return json({ ok: true, total_eligible_voters: totalVoters });
}

function getCanvasserName(pin) {
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Canvassers');
  if (!sheet) return 'Unknown';
  var rows = sheet.getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][1]) === String(pin)) return rows[i][0];
  }
  return 'Unknown';
}

function json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
