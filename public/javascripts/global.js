// Userlist data array for filling in info box
var userListData = [];

// DOM Ready =============================================================
$(document).ready(function () {
  if (window.location.pathname === '/admin') {
    adminRendering();
  } else {
    userRendering();
  }
});

// Functions =============================================================

// These are actions corresponding to the admin interface
function adminRendering() {
  // Populate the user table on initial page load
  populateTable();
  // Username link click
  $('.userList table tbody').on('click', 'td a.linkshowuser', showUserInfo);
  // Add User button click
  $('#btnAddUser').on('click', addUser);
  // Delete User link click
  $('.userList table tbody').on('click', 'td a.linkdeleteuser', deleteUser);
}

// More Functions for Admin Panel ========================================

// Fill table with data
function populateTable() {
  // Empty content string
  var tableContent = '';
  // jQuery AJAX call for JSON
  $.getJSON('/users/userlist', function (data) {
    // Stick our user data array into a userlist variable in the global object
    userListData = data;
    // For each item in our JSON, add a table row and cells to the content string
    $.each(data, function () {
      tableContent += '<tr>';
      tableContent += '<td><a href="#" class="linkshowuser" rel="' + this.username + '" title="Show Details">' + this.username + '</a></td>';
      tableContent += '<td>' + this.email + '</td>';
      tableContent += '<td><a href="#" class="linkdeleteuser" rel="' + this._id + '">delete</a></td>';
      tableContent += '</tr>';
    });
    // Inject the whole content string into our existing HTML table
    $('.userList table tbody').html(tableContent);
  });
};

// Show User Info
function showUserInfo(event) {
  // Prevent Link from Firing
  event.preventDefault();
  // Retrieve username from link rel attribute
  var thisUserName = $(this).attr('rel');
  // Get Index of object based on id value
  var arrayPosition = userListData.map(function (arrayItem) { return arrayItem.username; }).indexOf(thisUserName);
  // Get our User Object
  var thisUserObject = userListData[arrayPosition];
  //Populate Info Box
  $('#userInfoName').text(thisUserObject.fullname);
  $('#userInfoAge').text(thisUserObject.age);
  $('#userInfoCard').text(thisUserObject.card);
  $('#userInfoLocation').text(thisUserObject.location);
};

// Add User
function addUser(event) {
  event.preventDefault();
  // Super basic validation - increase errorCount variable if any fields are blank
  var errorCount = 0;
  $('#addUser input').each(function (index, val) {
    if ($(this).val() === '') { errorCount++; }
  });
  // Check and make sure errorCount's still at zero
  if (errorCount === 0) {
    // If it is, compile all user info into one object
    var newUser = {
      'username': $('#addUser fieldset input#inputUserName').val(),
      'email': $('#addUser fieldset input#inputUserEmail').val(),
      'fullname': $('#addUser fieldset input#inputUserFullname').val(),
      'age': $('#addUser fieldset input#inputUserAge').val(),
      'location': $('#addUser fieldset input#inputUserLocation').val(),
      'card': $('#addUser fieldset input#inputUserCard').val(),
      'password': $('#addUser fieldset input#inputUserName').val()
    }
    // Use AJAX to post the object to our adduser service
    $.ajax({
      type: 'POST',
      data: newUser,
      url: '/users/adduser',
      dataType: 'JSON'
    }).done(function (response) {
      // Check for successful (blank) response
      if (response.msg === '') {
        // Clear the form inputs
        $('#addUser fieldset input').val('');
        // Update the table
        populateTable();
      }
      else {
        // If something goes wrong, alert the error message that our service returned
        alert('Error: ' + response.msg);
      }
    });
  }
  else {
    // If errorCount is more than 0, error out
    alert('Please fill in all fields');
    return false;
  }
};

// Delete User
function deleteUser(event) {
  event.preventDefault();
  // Pop up a confirmation dialog
  var confirmation = confirm('Are you sure you want to delete this user?');
  // Check and make sure the user confirmed
  if (confirmation === true) {
    // If they did, do our delete
    $.ajax({
      type: 'DELETE',
      url: '/users/deleteuser/' + $(this).attr('rel')
    }).done(function (response) {
      // Check for a successful (blank) response
      if (response.msg === '') {
      }
      else {
        alert('Error: ' + response.msg);
      }
      // Update the table
      populateTable();
    });
  }
  else {
    // If they said no to the confirm, do nothing
    return false;
  }
};


// More Functions for User Panel =========================================

// These are actions corresponding to the user interface
function userRendering() {
  $('#btnLogin').on('click', loginUser);
  $('#btnLogout').on('click', logoutUser);
  $('#btnModify').on('click', modifyUser);
  initUserSession();
}

// initiate a user session when loading the page
function initUserSession() {
  $.ajax({
    type: 'POST',
    data: {},
    url: '/users/session',
    dataType: 'JSON'
  }).done(function (response) {
    if (response.user) {
      setLogin();
    } else {
      reset();
    }
  });
}

// function that logins the user when clicks login button
function loginUser() {
  event.preventDefault();
  var user = {
    'username': $('#login fieldset input#loginUserName').val(),
    'password': $('#login fieldset input#loginPassword').val(),
  }
  // Use AJAX to post the object to our adduser service
  $.ajax({
    type: 'POST',
    data: user,
    url: '/users/session',
    dataType: 'JSON'
  }).done(function (response) {
    // Check for successful response
    // can add  === user.username
    if (response && response.username) {
      setLogin();
    } else {
      // If something goes wrong, alert the error message that our service returned
      alert('Error: ' + response.msg);
    }
  });
};

// function that ends a user session
function logoutUser() {
  event.preventDefault();
  $.ajax({
    type: 'DELETE',
    url: '/users/session'
  }).done(function () {
    reset();
  });
}

// set the interface after login
function setLogin() {
  // hide the form inputs
  $('#login .userList fieldset input').hide();
  // show logout button
  $('#btnLogin').hide();
  $('#btnLogout').show();
  $('#modifyList').show();
  populateUserInfo();
}

// reset after user log out
function reset() {
  // hide the form inputs
  $('#login .userList fieldset input').show();
  // show logout button
  $('#btnLogin').show();
  $('#btnLogout').hide();
  // clear table
  $('#myInfoName').text('');
  $('#myInfoAge').text('');
  $('#myInfoCard').text('');
  $('#myInfoLocation').text('');
  $('#modifyList').hide();
}

// populate user info onto the My info table
function populateUserInfo() {
  // jQuery AJAX call for JSON
  $.getJSON('/users', function (data) {
    //Populate Info Box
    $('#myInfoName').text(data.user.fullname);
    $('#myInfoAge').text(data.user.age);
    $('#myInfoCard').text(data.user.card);
    $('#myInfoLocation').text(data.user.location);
  });
};

// modify uservalue
function modifyUser() {
  event.preventDefault();
  var modifyUser = {
    'password': $('#modifyPassword').val(),
    'email': $('#modifyUserEmail').val(),
    'fullname': $('#modifyUserFullname').val(),
    'age': $('#modifyUserAge').val(),
    'location': $('#modifyUserLocation').val(),
    'card': $('#modifyUserCard').val(),
  }
  // delete blank fields
  Object.keys(modifyUser).forEach((key) => { (modifyUser[key] === "") && delete modifyUser[key] });
  $.ajax({
    type: "PUT",
    data: modifyUser,
    url: '/users/modify',
    dataType: 'JSON',
  }).done(function (response) {
    // Check for successful (blank) response
    if (response.msg === '') {
      // after sucessful modification, update on the table
      setLogin();
      $('#modifyPassword').val('');
      $('#modifyUserEmail').val('');
      $('#modifyUserFullname').val('');
      $('#modifyUserAge').val('');
      $('#modifyUserLocation').val('');
      $('#modifyUserCard').val('');
    }
    else {
      // If something goes wrong, alert the error message that our service returned
      alert('Error: ' + response.msg);
    }
  });
}

// Functions =============================================================