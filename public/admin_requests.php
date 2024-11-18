<?php
require_once 'header.php';
require_once '..\includes\functions.php';

//Check if user is logged in and is admin
checkAccess('admin');

// Fetch evaluation requests from the database
$requests = fetchEvaluationRequests($pdo);
if ($requests === false) {
    $error_message = "An error occurred while fetching the requests. Please try again later.";
}
?>

<!-- Main Content Area -->
<div class="container my-4">
    <h2 class="mb-4">Evaluation Requests</h2>

    <?php if (isset($error_message)): ?>
        <div class="alert alert-danger" role="alert">
            <?php echo escape($error_message); ?>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-striped table-bordered align-middle">
                <thead class="table-dark">
                    <tr>
                        <th scope="col">#</th>
                        <th scope="col">User Name</th>
                        <th scope="col">Email</th>
                        <th scope="col">Phone</th>
                        <th scope="col">Details</th>
                        <th scope="col">Preferred Contact</th>
                        <th scope="col">Photo</th>
                        <th scope="col">Request Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (count($requests) === 0): ?>
                        <tr>
                            <td colspan="8" class="text-center">No evaluation requests found.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($requests as $request): ?>
                            <tr>
                                <th scope="row"><?php echo escape($request['id']); ?></th>
                                <td><?php echo escape($request['name']); ?></td>
                                <td><?php echo escape($request['email']); ?></td>
                                <td><?php echo escape($request['phone']); ?></td>
                                <td><?php echo nl2br(escape($request['details'])); ?></td>
                                <td><?php echo ucfirst(escape($request['preferred_contact'])); ?></td>
                                <td>
                                    <?php if (!empty($request['photo'])): ?>
                                        <a href="uploads/<?php echo escape($request['photo']); ?>" target="_blank">
                                            <img src="uploads/<?php echo escape($request['photo']); ?>" alt="Antique Photo" width="100">
                                        </a>
                                    <?php else: ?>
                                        <span>No Photo</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo escape($request['request_date']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php
require_once 'footer.php';
?>
